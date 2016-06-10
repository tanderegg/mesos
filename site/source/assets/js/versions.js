$(document).ready(function() {

  // Extract the current version and current page from the path
  var path_regex = /^\/documentation\/(?:(latest|[0-9]+\.[0-9]+\.[0-9]+)\/([a-z0-9\-\+\_\/\.]+)?\/?)?$/;
  var path_matches = path_regex.exec(window.location.pathname);

  var current_version = path_matches[1];
  var current_page = path_matches[2];

  if (current_version === undefined) {
    current_version = "latest";
  }

  // Set the select box to the current version
  $("#version-select").val(current_version);

  // On change of the select box, redirect to the current page on the selected
  // version, if it exists.
  $("#version-select").change(function() {
    var version = $(this).val();

    var path = "/documentation/" + version + "/"
    if (current_page !== undefined) {
      path = path + current_page
    }

    // Ensure that the current page exists for the desired doc version,
    // or else alert the user and redirect to the home page for that version.
    $.ajax(path, {
      statusCode: {
        404: function() {
          alert("Page '" + current_page + "' does not exist for Mesos version " + version + ".");
          path = "/documentation/" + version + "/";
        }
      },
      async: false
    });

    window.location.href=path;
  });
});
