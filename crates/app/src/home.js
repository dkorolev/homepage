// Toggles the debug view in place; `pushState` makes "back" return to the previous view.
(function() {
  function show(debug) {
    document.querySelectorAll('[data-debug]').forEach(function(e) { e.hidden = !debug; });
    document.getElementById('more').hidden = debug;
  }
  function toggle(id, debug) {
    document.querySelector('#' + id + ' a').addEventListener('click', function(e) {
      if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button !== 0) return;
      e.preventDefault();
      history.pushState({ debug: debug }, '', debug ? '?debug' : location.pathname);
      show(debug);
    });
  }
  toggle('more', true);
  toggle('less', false);
  window.addEventListener('popstate', function() {
    show(new URLSearchParams(location.search).has('debug'));
  });
})();
