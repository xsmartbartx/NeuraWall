// Sign in with NEXORA returns to "/#sso_token=...&state=...". The console lives at /app.
(function () {
  if (location.hash.indexOf("#sso_token=") === 0) {
    location.replace("/app/" + location.hash);
  }
})();
