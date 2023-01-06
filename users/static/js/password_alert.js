function updatePassword() {
    var txt = "Password updated successfully";
    document.getElementById("updatePassword").innerHTML = txt;
    document.getElementById('wrongPassword').style.display = "none";
    document.getElementById('updatePassword').style.display = "block";

  }

  function wrongPassword() {
    var txt = "Wrong Password. Please try again.";
    document.getElementById("wrongPassword").innerHTML = txt;
    document.getElementById('wrongPassword').style.display = "block";
    document.getElementById('updatePassword').style.display = "none";

  }