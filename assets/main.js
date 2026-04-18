'use strict';

// ─── Header ─────────────────────────────────────────────────────────────────
function initHeader() {
  var header = document.getElementById('header');
  if (!header) return;
  // Hero claro - header sempre sólido (sem toggle transparente)
  header.classList.add('header--scrolled');
}

// ─── Menu Mobile ────────────────────────────────────────────────────────────
function toggleMenu() {
  var header = document.getElementById('header');
  var btn = document.getElementById('menuToggle');
  if (!header || !btn) return;
  var isOpen = header.classList.toggle('header--open');
  btn.setAttribute('aria-expanded', String(isOpen));
}

function initMenu() {
  var btn = document.getElementById('menuToggle');
  if (btn) btn.addEventListener('click', toggleMenu);
  var links = document.querySelectorAll('.header__nav a');
  links.forEach(function(link) {
    link.addEventListener('click', function() {
      var header = document.getElementById('header');
      var menuBtn = document.getElementById('menuToggle');
      if (header) header.classList.remove('header--open');
      if (menuBtn) menuBtn.setAttribute('aria-expanded', 'false');
    });
  });
}

// ─── Turnstile (auto-render) ───────────────────────────────────────────────
function getTurnstileToken() {
  var input = document.querySelector('[name="cf-turnstile-response"]');
  return input ? input.value || '' : '';
}

function resetTurnstile() {
  if (typeof window.turnstile !== 'undefined') window.turnstile.reset();
}

// ─── Formulario de Adocao ───────────────────────────────────────────────────
function submitForm(e) {
  if (e && e.preventDefault) e.preventDefault();
  var consentEl = document.querySelector('[name="consent"]');
  var feedback = document.querySelector('.form-feedback');
  if (!consentEl || !consentEl.checked) {
    if (feedback) {
      feedback.textContent = 'Você precisa aceitar os termos para continuar.';
      feedback.className = 'form-feedback form-feedback--error';
    }
    return Promise.resolve();
  }
  var nomeEl = document.getElementById('nome');
  var sobrenomeEl = document.getElementById('sobrenome');
  var emailEl = document.getElementById('email');
  var telefoneEl = document.getElementById('telefone');
  var nome = nomeEl ? nomeEl.value.trim() : '';
  var sobrenome = sobrenomeEl ? sobrenomeEl.value.trim() : '';
  var email = emailEl ? emailEl.value.trim() : '';
  var telefone = telefoneEl ? telefoneEl.value.trim() : '';

  var nomeCompleto = sobrenome ? nome + ' ' + sobrenome : nome;

  var turnstileToken = getTurnstileToken();

  return fetch('/api/adocao', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ nome: nomeCompleto, email: email, telefone: telefone, especie: 'gatos', consent: true, 'cf-turnstile-response': turnstileToken }),
  }).then(function(res) {
    return res.json().then(function(data) {
      if (res.ok && data.success) {
        var form = document.getElementById('adoptForm');
        if (form) form.reset();
        if (feedback) {
          feedback.textContent = 'Recebemos sua solicitação! Entraremos em contato em breve.';
          feedback.className = 'form-feedback form-feedback--success';
        }
        resetTurnstile();
      } else {
        throw new Error('server error');
      }
    });
  }).catch(function() {
    if (feedback) {
      feedback.textContent = 'Ocorreu um erro. Por favor, tente novamente.';
      feedback.className = 'form-feedback form-feedback--error';
    }
    resetTurnstile();
  });
}

function initForm() {
  var form = document.getElementById('adoptForm');
  if (form) form.addEventListener('submit', submitForm);
}

// ─── Fade-in Observer ───────────────────────────────────────────────────────
function initFadeIn() {
  if (!('IntersectionObserver' in window)) return;
  var els = document.querySelectorAll('.fade-in');
  var observer = new IntersectionObserver(function(entries) {
    entries.forEach(function(entry) {
      if (entry.isIntersecting) {
        entry.target.classList.add('fade-in--visible');
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: 0.1 });
  els.forEach(function(el) { observer.observe(el); });
}

// ─── Cookie Banner ──────────────────────────────────────────────────────────
function initCookieBanner() {
  var banner = document.getElementById('cookie-banner');
  var COOKIE_KEY = 'amahcats_cookies_accepted';

  if (banner) {
    var stored = localStorage.getItem(COOKIE_KEY);
    if (!stored) {
      banner.classList.add('is-visible');
    }

    var acceptBtn = document.getElementById('cookie-accept');
    var settingsBtn = document.getElementById('cookie-settings');

    if (acceptBtn) {
      acceptBtn.addEventListener('click', function() {
        localStorage.setItem(COOKIE_KEY, 'all');
        banner.classList.remove('is-visible');
      });
    }

    if (settingsBtn) {
      settingsBtn.addEventListener('click', function() {
        localStorage.setItem(COOKIE_KEY, 'essential');
        banner.classList.remove('is-visible');
      });
    }
  }
}

// ─── Init (browser only) ────────────────────────────────────────────────────
function init() {
  initHeader();
  initMenu();
  initForm();
  initFadeIn();
  initCookieBanner();
}

if (typeof document !== 'undefined' && typeof module === 'undefined') {
  document.addEventListener('DOMContentLoaded', init);
}

// ─── Exports (CommonJS para Jest) ───────────────────────────────────────────
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    initHeader: initHeader,
    toggleMenu: toggleMenu,
    initMenu: initMenu,
    getTurnstileToken: getTurnstileToken,
    resetTurnstile: resetTurnstile,
    submitForm: submitForm,
    initForm: initForm,
    initFadeIn: initFadeIn,
    initCookieBanner: initCookieBanner,
    init: init,
  };
}
