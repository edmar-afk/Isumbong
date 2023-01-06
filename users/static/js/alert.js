function createComplaint() {
    var txt = "Complaint created successfully";
    document.getElementById("createComplaint").innerHTML = txt;
    document.getElementById('createComplaint').style.display = "block";
    document.getElementById('deleteComplaint').style.display = "none";
    document.getElementById('updateComplaint').style.display = "none";
  }


  function deleteComplaint() {
    var txt = "Complaint deleted successfully";
    document.getElementById("deleteComplaint").innerHTML = txt;
    document.getElementById('createComplaint').style.display = "none";
    document.getElementById('deleteComplaint').style.display = "block";
    document.getElementById('updateComplaint').style.display = "none";
  }

  function updateComplaint() {
    var txt = "Complaint updated successfully";
    document.getElementById("updateComplaint").innerHTML = txt;
    document.getElementById('createComplaint').style.display = "none";
    document.getElementById('deleteComplaint').style.display = "none";
    document.getElementById('updateComplaint').style.display = "block";

  }

  function fileComplaint() {
    var x = "Complaint submitted successfully";
    document.getElementById("fileComplaint").innerHTML = x;
    document.getElementById('fileComplaint').style.display = "block";
  }