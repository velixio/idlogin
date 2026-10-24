// Optional progressive enhancement: show/hide password buttons. Every page
// works without JavaScript; the buttons stay hidden then.
document.querySelectorAll("button[data-reveal]").forEach(function (btn) {
  var input = document.getElementById(btn.getAttribute("data-reveal"));
  if (!input) return;
  btn.hidden = false;
  btn.setAttribute("aria-label", "Show password");
  btn.addEventListener("click", function () {
    var show = input.type === "password";
    input.type = show ? "text" : "password";
    btn.textContent = show ? "Hide" : "Show";
    btn.setAttribute("aria-label", (show ? "Hide" : "Show") + " password");
    btn.setAttribute("aria-pressed", show ? "true" : "false");
  });
});
