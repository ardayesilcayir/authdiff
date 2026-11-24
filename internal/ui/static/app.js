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

  // --- Wizard -----------------------------------------------------------

  function each(list, fn) {
    Array.prototype.forEach.call(list, fn);
  }

  // Endpoints: "select all / none" for the row checkboxes.
  function initSelectAll() {
    each(document.querySelectorAll("[data-select-all]"), function (box) {
      var name = box.getAttribute("data-select-all");
      box.hidden = false;
      each(box.querySelectorAll("button[data-select]"), function (b) {
        b.addEventListener("click", function () {
          var on = b.getAttribute("data-select") === "all";
          each(document.querySelectorAll('input[type=checkbox][name="' + name + '"]'), function (c) {
            c.checked = on;
          });
        });
      });
    });
  }

  // Profiles: show only the fields the chosen sign-in type uses.
  function applyAuth(select) {
    var card = select.closest("[data-card]");
    if (!card) {
      return;
    }
    each(card.querySelectorAll("[data-auth]"), function (f) {
      var types = f.getAttribute("data-auth").split(" ");
      f.hidden = types.indexOf(select.value) < 0;
    });
  }

  // renumber rewrites the "<prefix><old>." part of name, id, for and
  // aria-describedby attributes inside el to use index n.
  function renumber(el, prefix, n) {
    var re = new RegExp("^" + prefix + "[0-9]+[.]");
    var attrs = ["name", "id", "for", "aria-describedby"];
    each(el.querySelectorAll("*"), function (node) {
      attrs.forEach(function (a) {
        var v = node.getAttribute(a);
        if (v) {
          node.setAttribute(a, v.split(" ").map(function (part) {
            return part.replace(re, prefix + n + ".");
          }).join(" "));
        }
      });
    });
    el.setAttribute("data-index", String(n));
  }

  // clearFields empties the copied inputs and drops copied error messages.
  function clearFields(el) {
    each(el.querySelectorAll("input"), function (i) {
      if (i.type === "checkbox") {
        i.checked = false;
      } else {
        i.value = "";
      }
      i.removeAttribute("aria-invalid");
    });
    each(el.querySelectorAll(".err, .remove"), function (e) {
      e.parentNode.removeChild(e);
    });
  }

  function nextIndex(items) {
    var max = -1;
    each(items, function (it) {
      var n = parseInt(it.getAttribute("data-index"), 10);
      if (n > max) {
        max = n;
      }
    });
    return max + 1;
  }

  // Adds a copy of the last item of container (a profile card or a matrix
  // row) with fresh field names. Without JS the page always carries one
  // empty item and a "save and add another" button.
  function initAdder(buttonId, attr, itemSel, prefix, onAdd) {
    var b = document.getElementById(buttonId);
    if (!b) {
      return;
    }
    var container = document.getElementById(b.getAttribute(attr));
    if (!container) {
      return;
    }
    b.hidden = false;
    b.addEventListener("click", function () {
      var items = container.querySelectorAll(itemSel);
      if (!items.length) {
        return;
      }
      var copy = items[items.length - 1].cloneNode(true);
      renumber(copy, prefix, nextIndex(items));
      clearFields(copy);
      container.appendChild(copy);
      if (onAdd) {
        onAdd(copy);
      }
      var first = copy.querySelector("input[type=text]");
      if (first) {
        first.focus();
      }
    });
  }

  function initProfiles() {
    each(document.querySelectorAll("select[data-auth-select]"), applyAuth);
    document.addEventListener("change", function (e) {
      if (e.target.matches && e.target.matches("select[data-auth-select]")) {
        applyAuth(e.target);
      }
    });
    initAdder("add-profile", "data-cards", "[data-card]", "p", function (card) {
      var legend = card.querySelector("legend");
      var blank = document.getElementById("add-profile").getAttribute("data-new-label");
      if (legend && blank) {
        legend.textContent = blank;
      }
      var tok = card.querySelectorAll("input[type=password], input[name$='.username']");
      each(tok, function (i) {
        i.removeAttribute("placeholder");
      });
      var role = card.querySelector("select[name$='.role']");
      if (role) {
        role.value = "user";
      }
      var auth = card.querySelector("select[data-auth-select]");
      if (auth) {
        auth.value = "bearer";
        applyAuth(auth);
      }
    });
    initAdder("add-row", "data-rows", "tr[data-row]", "m");
  }

  // Settings: turning on destructive mode opens a confirmation dialog that
  // fills the server-checked confirm field. Without JS (or <dialog>) the
  // field is typed directly; the server decides either way.
  function initDestructive() {
    var box = document.querySelector("input[data-confirm-dialog]");
    if (!box || box.hasAttribute("data-confirmed")) {
      return;
    }
    var dlg = document.getElementById(box.getAttribute("data-confirm-dialog"));
    var field = document.getElementById("confirm");
    if (!dlg || typeof dlg.showModal !== "function" || !field) {
      return;
    }
    var input = dlg.querySelector("input");
    function cancel() {
      box.checked = false;
      if (dlg.open) {
        dlg.close();
      }
    }
    box.addEventListener("change", function () {
      if (!box.checked) {
        return;
      }
      input.value = field.value;
      dlg.showModal();
      input.focus();
    });
    dlg.addEventListener("cancel", function (e) {
      e.preventDefault();
      cancel();
      box.focus();
    });
    dlg.addEventListener("click", function (e) {
      var act = e.target.getAttribute && e.target.getAttribute("data-dialog");
      if (act === "ok") {
        field.value = input.value;
        dlg.close();
        box.focus();
      } else if (act === "cancel") {
        cancel();
        box.focus();
      }
    });
  }

  // Buttons with data-confirm ask before submitting (project deletion).
  document.addEventListener("click", function (e) {
    var b = e.target.closest ? e.target.closest("button[data-confirm]") : null;
    if (b && !window.confirm(b.getAttribute("data-confirm"))) {
      e.preventDefault();
    }
  });

  // --- Live scan ----------------------------------------------------------

  // Run page: <section data-events="/api/runs/ID/events">. Without JS the
  // page refreshes itself every 3 s (noscript meta refresh); with JS the
  // counters and preliminary findings update from Server-Sent Events.
  function localPath(p) {
    return typeof p === "string" && p.charAt(0) === "/" && p.charAt(1) !== "/" && p.indexOf("\\") < 0;
  }

  function initRun() {
    var root = document.querySelector("section[data-events]");
    if (!root || typeof window.EventSource !== "function") {
      return;
    }
    function field(name) {
      return root.querySelector('[data-field="' + name + '"]');
    }
    function set(name, text) {
      var el = field(name);
      if (el) {
        el.textContent = String(text);
      }
    }
    var bar = document.getElementById("run-progress");
    var finished = false;

    function progress(d) {
      set("sent", d.sent);
      set("planned", d.planned);
      set("blocked", d.blocked);
      set("errors", d.errors);
      set("findings", d.findings);
      set("phase", root.getAttribute("data-phase-label") + " " + (d.phaseName || ""));
      var parts = [];
      Object.keys(d.severity || {}).sort().forEach(function (k) {
        parts.push(k + " " + d.severity[k]);
      });
      set("severity", parts.length ? "(" + parts.join(" · ") + ")" : "");
      if (bar) {
        bar.value = d.percent;
        bar.textContent = d.percent + "%";
      }
    }

    function el(tag, cls, text) {
      var e = document.createElement(tag);
      if (cls) {
        e.className = cls;
      }
      if (text !== undefined) {
        e.textContent = text;
      }
      return e;
    }

    var seen = {};
    each(root.querySelectorAll('[data-field="list"] li[data-id]'), function (li) {
      seen[li.getAttribute("data-id")] = true;
    });
    function addFinding(f) {
      if (seen[f.id]) {
        return;
      }
      seen[f.id] = true;
      var list = field("list");
      if (!list) {
        return;
      }
      var li = el("li");
      li.appendChild(el("span", "muted", f.time));
      li.appendChild(document.createTextNode(" "));
      var sev = /^[a-z]+$/.test(f.severity) ? f.severity : "info";
      li.appendChild(el("span", "tag " + sev, f.severity));
      li.appendChild(document.createTextNode(" "));
      li.appendChild(el("code", "", f.ruleId));
      li.appendChild(document.createTextNode(" "));
      li.appendChild(el("code", "", f.method + " " + f.path));
      if (f.attacker) {
        li.appendChild(document.createTextNode(" "));
        li.appendChild(el("span", "muted", f.attacker + " → " + (f.victim || "")));
      }
      list.insertBefore(li, list.firstChild);
      var empty = field("empty");
      if (empty) {
        empty.hidden = true;
      }
    }

    function message(text) {
      var m = field("message");
      if (m) {
        m.textContent = text;
        m.hidden = !text;
      }
    }

    function stopForm(hide) {
      var f = root.querySelector("form[data-stop] button");
      if (f) {
        f.hidden = hide;
      }
    }

    var es = new window.EventSource(root.getAttribute("data-events"));
    es.addEventListener("progress", function (e) {
      progress(JSON.parse(e.data));
    });
    es.addEventListener("finding", function (e) {
      addFinding(JSON.parse(e.data));
    });
    es.addEventListener("done", function (e) {
      finished = true;
      es.close();
      var d = JSON.parse(e.data);
      set("sent", d.sent);
      set("blocked", d.blocked);
      set("errors", d.errors);
      set("findings", d.findings);
      if (bar) {
        bar.value = 100;
        bar.textContent = "100%";
      }
      stopForm(true);
      var link = root.querySelector("a[data-results]");
      if (link && localPath(d.results)) {
        link.href = d.results;
        link.hidden = false;
      }
      if (d.status === "failed") {
        set("status", root.getAttribute("data-failed-label"));
        message(d.message || "");
        return;
      }
      set("status", root.getAttribute(d.status === "stopped" ? "data-stopped-label" : "data-done-label"));
      if (localPath(d.results)) {
        window.setTimeout(function () {
          window.location.assign(d.results);
        }, 800);
      }
    });
    es.addEventListener("error", function (e) {
      if (e.data) { // the run's own error event
        finished = true;
        es.close();
        stopForm(true);
        set("status", root.getAttribute("data-error-label"));
        message(JSON.parse(e.data).message || "");
        return;
      }
      // A connection error: EventSource retries on its own unless closed.
      if (!finished && es.readyState === window.EventSource.CLOSED) {
        message(root.getAttribute("data-lost-label"));
      }
    });
  }

  function init() {
    initCopy();
    initSelectAll();
    initProfiles();
    initDestructive();
    initRun();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
