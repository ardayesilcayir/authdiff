// authdiff ui: small progressive enhancements. Data reaches the DOM only
// through textContent / createElement (never HTML strings); the CSP allows
// no inline script.
(function () {
  "use strict";

  // Copy buttons: <button data-copy="ID" data-done="..." data-failed="...">
  // copy the text of element ID. They start hidden and appear only when
  // the clipboard is available.
  function initCopy() {
    if (!navigator.clipboard || !navigator.clipboard.writeText) {
      return;
    }
    var buttons = document.querySelectorAll("button[data-copy]");
    Array.prototype.forEach.call(buttons, function (b) {
      b.hidden = false;
      b.setAttribute("aria-live", "polite");
    });
  }

  document.addEventListener("click", function (e) {
    var b = e.target.closest ? e.target.closest("button[data-copy]") : null;
    if (!b) {
      return;
    }
    var src = document.getElementById(b.getAttribute("data-copy"));
    if (!src) {
      return;
    }
    var label = b.getAttribute("data-label") || b.textContent;
    b.setAttribute("data-label", label);
    function show(text) {
      b.textContent = text;
      window.setTimeout(function () {
        b.textContent = label;
      }, 2000);
    }
    navigator.clipboard.writeText(src.textContent).then(
      function () { show(b.getAttribute("data-done")); },
      function () { show(b.getAttribute("data-failed")); }
    );
  });

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initCopy);
  } else {
    initCopy();
  }
})();
