$(document).ready(function() {

  // Extract the current version and current page from the path.
  var pathRegex = /^\/documentation\/(?:(latest|[0-9]+\.[0-9]+\.[0-9]+)\/([a-z0-9\-\+\_\/\.]+)?\/?)?$/;
  var pathMatches = pathRegex.exec(window.location.pathname);

  var currentVersion = pathMatches[1];
  var currentPage = pathMatches[2];

  if (currentVersion === undefined) {
    currentVersion = "latest";
  }

  // Set the select box to the current version.
  $("#version-select").val(currentVersion);

  // On change of the select box, redirect to the current page on the selected
  // version, if it exists.
  $("#version-select").change(function() {
    var version = $(this).val();

    if (version != "") {
      var path = "/documentation/" + version + "/";
      if (currentPage !== undefined) {
        path = path + currentPage;
      }

      // Ensure that the current page exists for the desired doc version,
      // or else alert the user and redirect to the home page for that version.
      $.ajax(path, {
        statusCode: {
          404: function() {
            alert("Page '" + currentPage + "' does not exist for Mesos version " + version + ".");
            path = "/documentation/" + version + "/";
          }
        },
        async: false
      });

      window.location.href = path;
    }
  });
});
