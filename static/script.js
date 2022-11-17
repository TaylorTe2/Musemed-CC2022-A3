function displaySpotifyForm() {
    // var youtubeButton = document.getElementById("youtube");
    var spotifyButton = document.getElementById("spotify");
    var text = document.getElementById("soyl");

    var spotifyInputField = document.createElement("input");
    spotifyInputField.setAttribute("type", "text");
    spotifyInputField.setAttribute("placeholder", "Insert Spotify URL");
    spotifyInputField.setAttribute("name", "song-input");

    var submitButton = document.createElement("input");
    submitButton.setAttribute("type", "submit")

    document.getElementById("link-form").appendChild(spotifyInputField);
    document.getElementById("link-form").appendChild(submitButton);

    // youtubeButton.remove();
    spotifyButton.remove();
    text.remove();
}

function displayYoutubeForm() {
    var youtubeButton = document.getElementById("youtube");
    var spotifyButton = document.getElementById("spotify");
    var text = document.getElementById("soyl");

    var youtubeInputField = document.createElement("input");
    youtubeInputField.setAttribute("type", "text");
    youtubeInputField.setAttribute("placeholder", "Insert Youtube Link");
    youtubeInputField.setAttribute("name", "song-input");

    var submitButton = document.createElement("input");
    submitButton.setAttribute("type", "submit");

    document.getElementById("link-form").appendChild(youtubeInputField);
    document.getElementById("link-form").appendChild(submitButton);

    youtubeButton.remove();
    spotifyButton.remove();
    text.remove();
}