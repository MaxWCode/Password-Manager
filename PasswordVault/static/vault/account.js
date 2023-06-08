setTimeout(function() {
    var vaultMessagesContainer = document.getElementById("fade");
    vaultMessagesContainer.style.transition = "opacity 0.5s";
    vaultMessagesContainer.style.opacity = "0";
    
    setTimeout(function() {
        vaultMessagesContainer.style.display = "none";
    }, 125);
}, 1500);
