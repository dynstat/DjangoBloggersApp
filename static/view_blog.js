let g_url = "";

document.addEventListener("DOMContentLoaded", function () {

    g_url = generateRandomUrlSafeString(6)
});
function toggleForm() {
    var form = document.getElementById('popup-form');
    form.style.display = form.style.display === 'none' ? 'block' : 'none';

    url_inp_field = document.getElementById("published-url")
    url_inp_field.value = g_url;


}

function copyUrl() {
    var urlInput = document.getElementById('published-url');
    urlInput.select();
    document.execCommand('copy');
}



function display_url() {
    var url_elem = document.getElementById("pub_url");
    url = `http://www.abcd.com/pub/${generateRandomUrlSafeString(6)}`
    url_elem.innerHTML = "<a href='" + url + "'>" + url + "</a>";

    var data = {
        key1: url,
        // Add other data as needed
    };
    // var csrftoken = getCookie('csrftoken');  # not working
    var csrftoken = Cookies.get('csrftoken');

    // Send the POST request
    fetch('/urltodb/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': csrftoken,
        },
        body: JSON.stringify(data),
    })
        .then(function (response) {
            // Handle the response from the server
            if (response.ok) {
                // Request successful
                // ...
            } else {
                // Request failed
                // ...
            }
        })
        .catch(function (error) {
            // Handle any errors that occur during the request
            // ...
        });
}

function generateRandomUrlSafeString(length) {
    var chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_';
    var randomString = '';

    for (var i = 0; i < length; i++) {
        var randomIndex = Math.floor(Math.random() * chars.length);
        randomString += chars.charAt(randomIndex);
    }

    var urlSafeString = encodeURIComponent(randomString);
    return urlSafeString;
}