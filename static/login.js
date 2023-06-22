console.log("Running login.js");
document.getElementById('signup-link').addEventListener('click', function (event) {
    event.preventDefault(); // Prevent the default behavior of the link

    console.log("Running signup modification");
    var queryParams = window.location.search; // Get the existing query parameters
    if (queryParams) {
        var signupUrl = '/signuppg' + queryParams; // Concatenate the query parameters with the signup URL

        window.location.href = signupUrl; // Navigate to the modified URL
        console.log("signup modified");
    }
});
