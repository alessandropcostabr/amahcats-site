'use strict';

// ─── Estado do wizard ────────────────────────────────────────────────────────
var currentStep = 0;

// ─── Navegação ───────────────────────────────────────────────────────────────
function goToStep(n) {
  var panels = document.querySelectorAll('.wizard__panel');
  var steps = document.querySelectorAll('.wizard__step');
  var totalSteps = 4; // steps de formulário (panels 0-3)

  n = Math.max(0, Math.min(n, totalSteps - 1));
  currentStep = n;

  panels.forEach(function(panel, i) {
    panel.classList.toggle('wizard__panel--active', i === n);
  });

  steps.forEach(function(step, i) {
    step.classList.toggle('wizard__step--done', i < n);
    step.classList.toggle('wizard__step--active', i === n);
  });

  var progress = document.querySelector('.wizard__progress');
  if (progress) {
    var stepLabels = ['Dados Pessoais', 'Sobre o Animal', 'Sua Residência', 'Tempo, Recursos e Revisão'];
    progress.textContent = 'Etapa ' + (n + 1) + ' de ' + totalSteps + ' - ' + (stepLabels[n] || '');
  }

  // Ultimo step: mudar texto do botao
  var btnNext = document.getElementById('btnNext');
  if (btnNext) {
    btnNext.textContent = (n === totalSteps - 1) ? 'Enviar formulário' : 'Próximo →';
  }
}

// ─── SessionStorage (LGPD: dados não persistem entre abas nem após fechar) ──
function saveProgress() {
  // Preservar opportunity_id do draft existente (setado pelo step 1)
  var existing = {};
  try { existing = JSON.parse(sessionStorage.getItem('iacd_adocao_draft') || '{}'); } catch (e) { /* ignore */ }

  var data = {};
  if (existing.opportunity_id) data.opportunity_id = existing.opportunity_id;
  if (existing.opportunity_sig) data.opportunity_sig = existing.opportunity_sig;
  data.currentStep = currentStep;

  // Campos de texto, select, textarea por ID
  // PII sensível (CPF, RG, data de nascimento) não é salva no sessionStorage (LGPD)
  var SENSITIVE_FIELDS = { cpf: true, rg: true, data_nascimento: true, cep: true, rua: true, numero: true, complemento: true, bairro: true, cidade: true, uf: true };
  var fields = document.querySelectorAll('input[id]:not([type="radio"]):not([type="checkbox"]), select[id], textarea[id]');
  fields.forEach(function(el) {
    if (SENSITIVE_FIELDS[el.id]) return;
    data[el.id] = el.value;
  });

  // Radio groups por name
  var radioNames = {};
  var radios = document.querySelectorAll('input[type="radio"]');
  radios.forEach(function(r) {
    radioNames[r.name] = true;
  });
  Object.keys(radioNames).forEach(function(name) {
    var checked = document.querySelector('input[type="radio"][name="' + name + '"]:checked');
    data[name] = checked ? checked.value : '';
  });

  sessionStorage.setItem('iacd_adocao_draft', JSON.stringify(data));
}

function restoreProgress() {
  // Cleanup de dados legados do localStorage (migração para sessionStorage)
  localStorage.removeItem('iacd_adocao_draft');
  localStorage.removeItem('iacd_pending_steps');

  var raw = sessionStorage.getItem('iacd_adocao_draft');
  if (!raw) return;

  var data;
  try {
    data = JSON.parse(raw);
  } catch (e) {
    return;
  }

  Object.keys(data).forEach(function(key) {
    if (key === 'currentStep') return;

    var el = document.getElementById(key);
    if (el) {
      el.value = data[key];
      return;
    }

    // Tentar como radio group por name
    var radio = document.querySelector('input[type="radio"][name="' + key + '"][value="' + data[key] + '"]');
    if (radio) {
      radio.checked = true;
    }
  });

  if (typeof data.currentStep === 'number') {
    goToStep(data.currentStep);
  }
}

function clearProgress() {
  sessionStorage.removeItem('iacd_adocao_draft');
}

// ─── Validação de CPF ────────────────────────────────────────────────────────
function validateCPF(cpf) {
  cpf = String(cpf).replace(/\D/g, '');
  if (cpf.length !== 11) return false;

  // Rejeitar sequências com todos os dígitos iguais
  if (/^(\d)\1{10}$/.test(cpf)) return false;

  // Primeiro dígito verificador
  var sum = 0;
  for (var i = 0; i < 9; i++) {
    sum += parseInt(cpf[i]) * (10 - i);
  }
  var remainder = sum % 11;
  var digit1 = remainder < 2 ? 0 : 11 - remainder;
  if (parseInt(cpf[9]) !== digit1) return false;

  // Segundo dígito verificador
  sum = 0;
  for (var j = 0; j < 10; j++) {
    sum += parseInt(cpf[j]) * (11 - j);
  }
  remainder = sum % 11;
  var digit2 = remainder < 2 ? 0 : 11 - remainder;
  if (parseInt(cpf[10]) !== digit2) return false;

  return true;
}

// ─── Validação de Idade ──────────────────────────────────────────────────────
function validateAge(dateStr) {
  var parts = dateStr.split('-');
  var birthDate = new Date(parseInt(parts[0]), parseInt(parts[1]) - 1, parseInt(parts[2]));
  var today = new Date();
  var age = today.getFullYear() - birthDate.getFullYear();
  var m = today.getMonth() - birthDate.getMonth();
  if (m < 0 || (m === 0 && today.getDate() < birthDate.getDate())) {
    age--;
  }
  return age >= 18;
}

// ─── Limpar estado de erro de um campo ──────────────────────────────────────
function clearFieldError(el) {
  if (el.type === 'radio') {
    var group = el.closest('.radio-group');
    if (group) group.classList.remove('invalid');
  } else if (el.type === 'checkbox') {
    var consent = el.closest('.consent-group');
    if (consent) consent.classList.remove('invalid');
  } else {
    el.classList.remove('invalid');
  }
}

// ─── Validação de Step ───────────────────────────────────────────────────────
function validateStep(stepIndex) {
  var panel = document.querySelector('.wizard__panel[data-step="' + stepIndex + '"]');
  if (!panel) return false;

  // Limpar erros anteriores do painel
  panel.querySelectorAll('.invalid').forEach(function(el) {
    el.classList.remove('invalid');
  });
  var alert = panel.querySelector('.validation-alert');
  if (alert) {
    alert.classList.remove('validation-alert--visible');
    alert.textContent = '';
  }

  var required = panel.querySelectorAll('[required]');
  var radioNamesChecked = {};
  var valid = true;
  var firstInvalid = null;
  var invalidCount = 0;

  required.forEach(function(el) {
    // Defesa em profundidade: pular campos dentro de .conditional oculto
    var container = el.closest('.conditional');
    if (container && !container.classList.contains('conditional--visible')) return;

    if (el.type === 'radio') {
      if (radioNamesChecked[el.name] !== undefined) return;
      var checked = panel.querySelector('input[type="radio"][name="' + el.name + '"]:checked');
      radioNamesChecked[el.name] = !!checked;
      if (!checked) {
        valid = false;
        invalidCount++;
        var group = el.closest('.radio-group');
        if (group) group.classList.add('invalid');
        if (!firstInvalid) firstInvalid = group || el;
      }
    } else if (el.type === 'checkbox') {
      if (!el.checked) {
        valid = false;
        invalidCount++;
        var consent = el.closest('.consent-group');
        if (consent) consent.classList.add('invalid');
        if (!firstInvalid) firstInvalid = consent || el;
      }
    } else {
      if (!el.value.trim()) {
        valid = false;
        invalidCount++;
        el.classList.add('invalid');
        if (!firstInvalid) firstInvalid = el;
      }
    }
  });

  if (!valid && alert) {
    var msg = invalidCount === 1
      ? 'Preencha o campo destacado para continuar.'
      : 'Preencha os ' + invalidCount + ' campos destacados para continuar.';
    alert.textContent = msg;
    alert.classList.add('validation-alert--visible');
  }

  if (firstInvalid) {
    if (firstInvalid.scrollIntoView) {
      firstInvalid.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
    if (firstInvalid.focus && firstInvalid.tagName !== 'DIV') {
      firstInvalid.focus({ preventScroll: true });
    }
  }

  return valid;
}

// ─── Campos Condicionais (com required dinâmico) ────────────────────────────
function toggleConditional(id, show) {
  var el = document.getElementById(id);
  if (!el) return;
  if (show) {
    el.classList.add('conditional--visible');
    // Setar required nos inputs/textareas/selects filhos
    var inputs = el.querySelectorAll('input, textarea, select');
    inputs.forEach(function(input) { input.setAttribute('required', ''); });
  } else {
    el.classList.remove('conditional--visible');
    // Remover required e limpar valores
    var inputs = el.querySelectorAll('input, textarea, select');
    inputs.forEach(function(input) {
      input.removeAttribute('required');
      if (input.type === 'radio' || input.type === 'checkbox') {
        input.checked = false;
      } else {
        input.value = '';
      }
    });
  }
}

// Mapa de radios condicionais: name do grupo → { targetId, trigger }
var CONDITIONAL_RADIOS = {
  experiencia: { targetId: 'experiencia_detalhes', trigger: 'sim' },
  tem_criancas: { targetId: 'criancas_container', trigger: 'sim' },
  tem_animais: { targetId: 'animais_detalhes', trigger: 'sim' },
  alergia_familia: { targetId: 'alergia_detalhes', trigger: 'sim' },
  recursos_financeiros: { targetId: 'recursos_container', trigger: 'sim' },
};

// ─── Coleta de Dados ─────────────────────────────────────────────────────────
function collectFormData() {
  var data = {};

  // Campos de texto, select, textarea por ID
  var maskedFields = { cpf: true, telefone_form: true, cep: true };
  var fields = document.querySelectorAll('input[id]:not([type="radio"]):not([type="checkbox"]), select[id], textarea[id]');
  fields.forEach(function(el) {
    var val = el.value.trim();
    data[el.id] = maskedFields[el.id] ? val.replace(/\D/g, '') : val;
  });

  // Radio groups por name
  var radioNames = {};
  var radios = document.querySelectorAll('input[type="radio"]');
  radios.forEach(function(r) {
    radioNames[r.name] = true;
  });
  Object.keys(radioNames).forEach(function(name) {
    var checked = document.querySelector('input[type="radio"][name="' + name + '"]:checked');
    data[name] = checked ? checked.value : '';
  });

  // Consent checkbox
  var consentEl = document.getElementById('consent_form');
  data.consent = consentEl ? consentEl.checked : false;

  return data;
}

// ─── Submit ──────────────────────────────────────────────────────────────────
function submitForm() {
  var feedback = document.querySelector('.form-feedback');
  var consentEl = document.getElementById('consent_form');

  if (!consentEl || !consentEl.checked) {
    if (feedback) {
      feedback.textContent = 'Você precisa aceitar os termos para continuar.';
      feedback.className = 'form-feedback form-feedback--error';
    }
    return Promise.resolve();
  }

  var formData = collectFormData();

  return fetch('/api/entrevista', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(formData),
  }).then(function(res) {
    return res.json().then(function(data) {
      if (res.ok) {
        clearProgress();
        if (feedback) {
          if (data.pending) {
            feedback.textContent = 'Seus dados foram recebidos, mas estão sendo processados. Entraremos em contato em breve.';
            feedback.className = 'form-feedback form-feedback--warning';
          } else {
            feedback.textContent = 'Candidatura enviada com sucesso! Entraremos em contato em breve.';
            feedback.className = 'form-feedback form-feedback--success';
          }
        }
      } else {
        throw new Error('server error');
      }
    });
  }).catch(function() {
    if (feedback) {
      feedback.textContent = 'Ocorreu um erro. Por favor, tente novamente.';
      feedback.className = 'form-feedback form-feedback--error';
    }
  });
}

// ─── Pré-preenchimento via token ──────────────────────────────────────────────
function fetchPreFill(token) {
  if (!token) return;

  return fetch('/api/contato-preview?t=' + encodeURIComponent(token))
    .then(function(res) {
      if (!res.ok) return;
      return res.json().then(function(result) {
        var d = (result && result.data) || {};
        var nomeEl = document.getElementById('nome_completo');
        var emailEl = document.getElementById('email_form');
        var telEl = document.getElementById('telefone_form');
        if (nomeEl && d.nome) nomeEl.value = d.nome;
        if (emailEl && d.email) emailEl.value = d.email;
        if (telEl && d.telefone) telEl.value = d.telefone;
      });
    })
    .catch(function() {
      // erro silencioso - token inválido ou contato não encontrado
    });
}

// ─── Máscaras de Input ────────────────────────────────────────────────────────
function maskCPF(value) {
  var digits = String(value).replace(/\D/g, '').slice(0, 11);
  var len = digits.length;
  if (len <= 3) return digits;
  if (len <= 6) return digits.slice(0, 3) + '.' + digits.slice(3);
  if (len <= 9) return digits.slice(0, 3) + '.' + digits.slice(3, 6) + '.' + digits.slice(6);
  return digits.slice(0, 3) + '.' + digits.slice(3, 6) + '.' + digits.slice(6, 9) + '-' + digits.slice(9);
}

function maskPhone(value) {
  var digits = String(value).replace(/\D/g, '').slice(0, 11);
  var len = digits.length;
  if (len <= 2) return digits.length === 0 ? '' : '(' + digits;
  if (len <= 7) return '(' + digits.slice(0, 2) + ') ' + digits.slice(2);
  return '(' + digits.slice(0, 2) + ') ' + digits.slice(2, 7) + '-' + digits.slice(7);
}

function maskCEP(value) {
  var digits = String(value).replace(/\D/g, '').slice(0, 8);
  var len = digits.length;
  if (len <= 5) return digits;
  return digits.slice(0, 5) + '-' + digits.slice(5);
}

// ─── ViaCEP ───────────────────────────────────────────────────────────────────
function fetchViaCEP(cep) {
  var digits = String(cep).replace(/\D/g, '');
  if (digits.length !== 8) return Promise.resolve();

  return fetch('https://viacep.com.br/ws/' + digits + '/json/')
    .then(function(res) {
      if (!res.ok) return;
      return res.json().then(function(data) {
        if (data.erro) return;
        var ruaEl = document.getElementById('rua');
        var bairroEl = document.getElementById('bairro');
        var cidadeEl = document.getElementById('cidade');
        var ufEl = document.getElementById('uf');
        if (ruaEl) ruaEl.value = data.logradouro || '';
        if (bairroEl) bairroEl.value = data.bairro || '';
        if (cidadeEl) cidadeEl.value = data.localidade || '';
        if (ufEl) ufEl.value = data.uf || '';
      });
    })
    .catch(function() {
      // erro silencioso
    });
}

// ─── Coleta por step ────────────────────────────────────────────────────────
function collectStepData(stepNumber) {
  var panel = document.querySelector('.wizard__panel[data-step="' + stepNumber + '"]');
  if (!panel) return {};
  var data = {};
  var maskedFields = { cpf: true, telefone_form: true, cep: true };

  var fields = panel.querySelectorAll('input[id]:not([type="radio"]):not([type="checkbox"]), select[id], textarea[id]');
  fields.forEach(function(el) {
    var val = el.value.trim();
    data[el.id] = maskedFields[el.id] ? val.replace(/\D/g, '') : val;
  });

  var radioNames = {};
  var radios = panel.querySelectorAll('input[type="radio"]');
  radios.forEach(function(r) { radioNames[r.name] = true; });
  Object.keys(radioNames).forEach(function(name) {
    var checked = panel.querySelector('input[type="radio"][name="' + name + '"]:checked');
    data[name] = checked ? checked.value : '';
  });

  var consentEl = panel.querySelector('#consent_form');
  if (consentEl) data.consent = consentEl.checked;

  return data;
}

function buildStepPayload(stepNumber, data, opportunityId, opportunitySig) {
  return {
    step: stepNumber,
    data: data,
    opportunity_id: opportunityId || null,
    opportunity_sig: opportunitySig || null,
  };
}

// ─── Submit por step ─────────────────────────────────────────────────────────
function submitStep(stepNumber) {
  var feedback = document.querySelector('.form-feedback');

  // Step 4 (panel 3) — validar consent
  if (stepNumber === 3) {
    var consentEl = document.getElementById('consent_form');
    if (!consentEl || !consentEl.checked) {
      if (feedback) {
        feedback.textContent = 'Você precisa aceitar os termos para continuar.';
        feedback.className = 'form-feedback form-feedback--error';
      }
      return Promise.resolve();
    }
  }

  var data = collectStepData(stepNumber);
  var draft = JSON.parse(sessionStorage.getItem('iacd_adocao_draft') || '{}');
  var opportunityId = draft.opportunity_id || null;
  var opportunitySig = draft.opportunity_sig || null;
  // step number sent to API is stepNumber + 1 (panel 0 = step 1, panel 1 = step 2, etc.)
  var apiStep = stepNumber + 1;
  var payload = buildStepPayload(apiStep, data, opportunityId, opportunitySig);

  // Panel 0 (step 1): bloqueante — precisa do opportunity_id
  if (stepNumber === 0) {
    if (feedback) {
      feedback.textContent = 'Salvando dados...';
      feedback.className = 'form-feedback form-feedback--info';
    }
    return fetch('/api/entrevista', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    })
    .then(function(r) { return r.json(); })
    .then(function(result) {
      if (result.success && result.opportunity_id) {
        draft.opportunity_id = result.opportunity_id;
        draft.opportunity_sig = result.opportunity_sig || '';
        sessionStorage.setItem('iacd_adocao_draft', JSON.stringify(draft));
        if (feedback) feedback.textContent = '';
        saveProgress();
        goToStep(1);
      } else {
        if (feedback) {
          feedback.textContent = result.message || 'Erro ao salvar.';
          feedback.className = 'form-feedback form-feedback--error';
        }
      }
    })
    .catch(function() {
      if (feedback) {
        feedback.textContent = 'Erro de conexão. Tente novamente.';
        feedback.className = 'form-feedback form-feedback--error';
      }
    });
  }

  // Panels 1-2 (steps 2-3): fire-and-forget (contingência tratada no server)
  if (stepNumber === 1 || stepNumber === 2) {
    fetch('/api/entrevista', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    }).catch(function() {
      // Falha de rede - server cuida da contingência (JSON + email alerta)
    });
    saveProgress();
    goToStep(stepNumber + 1);
    return Promise.resolve();
  }

  // Panel 3 (step 4): bloqueante — finaliza
  if (stepNumber === 3) {
    if (feedback) {
      feedback.textContent = 'Enviando formulário...';
      feedback.className = 'form-feedback form-feedback--info';
    }

    return fetch('/api/entrevista', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    })
    .then(function(r) { return r.json(); })
    .then(function(result) {
      if (result.success) {
        clearProgress();
        // Mostrar tela de sucesso
        var panels = document.querySelectorAll('.wizard__panel');
        panels.forEach(function(p) { p.classList.remove('wizard__panel--active'); });
        var successPanel = document.querySelector('.wizard__success');
        if (successPanel) successPanel.classList.add('wizard__panel--active');
        // Esconder nav e feedback, marcar steps como done
        var nav = document.querySelector('.wizard__nav');
        if (nav) nav.style.display = 'none';
        if (feedback) feedback.textContent = '';
        var steps = document.querySelectorAll('.wizard__step');
        steps.forEach(function(s) { s.classList.add('wizard__step--done'); s.classList.remove('wizard__step--active'); });
        var progress = document.querySelector('.wizard__progress');
        if (progress) progress.textContent = 'Concluído!';
      } else {
        if (feedback) {
          feedback.textContent = result.message || 'Erro ao enviar.';
          feedback.className = 'form-feedback form-feedback--error';
        }
      }
    })
    .catch(function() {
      if (feedback) {
        feedback.textContent = 'Erro de conexão. Tente novamente.';
        feedback.className = 'form-feedback form-feedback--error';
      }
    });
  }

  return Promise.resolve();
}

// ─── Inicialização do Wizard ──────────────────────────────────────────────────
function initWizard() {
  var btnNext = document.getElementById('btnNext');
  var btnPrev = document.getElementById('btnPrev');

  if (btnNext) {
    btnNext.addEventListener('click', function() {
      if (validateStep(currentStep)) {
        submitStep(currentStep);
      }
    });
  }

  if (btnPrev) {
    btnPrev.addEventListener('click', function() {
      saveProgress();
      goToStep(currentStep - 1);
    });
  }

  // Campos condicionais — vincular AMBOS os radios de cada grupo (sim E não)
  Object.keys(CONDITIONAL_RADIOS).forEach(function(groupName) {
    var config = CONDITIONAL_RADIOS[groupName];
    var radios = document.querySelectorAll('input[type="radio"][name="' + groupName + '"]');
    radios.forEach(function(radio) {
      radio.addEventListener('change', function() {
        toggleConditional(config.targetId, this.value === config.trigger);
      });
    });
  });

  // Ler token da URL
  var token = null;
  if (typeof window !== 'undefined' && window.location && window.location.search) {
    var params = new URLSearchParams(window.location.search);
    token = params.get('t');
  }

  // Máscara CPF
  var cpfInput = document.getElementById('cpf');
  if (cpfInput) {
    cpfInput.addEventListener('input', function() {
      cpfInput.value = maskCPF(cpfInput.value);
    });
  }

  // Máscara telefone
  var telInput = document.getElementById('telefone_form');
  if (telInput) {
    telInput.addEventListener('input', function() {
      telInput.value = maskPhone(telInput.value);
    });
  }

  // Máscara CEP + ViaCEP
  var cepInput = document.getElementById('cep');
  if (cepInput) {
    cepInput.addEventListener('input', function() {
      cepInput.value = maskCEP(cepInput.value);
    });
    cepInput.addEventListener('blur', function() {
      fetchViaCEP(cepInput.value);
    });
  }

  // Limpar erro visual ao interagir com campos
  var wizardBody = document.querySelector('.wizard__body');
  if (wizardBody) {
    wizardBody.addEventListener('input', function(e) {
      clearFieldError(e.target);
    });
    wizardBody.addEventListener('change', function(e) {
      clearFieldError(e.target);
    });
  }

  restoreProgress();
  fetchPreFill(token);
}

// ─── Auto-init (browser sem module system) ───────────────────────────────────
if (typeof document !== 'undefined' && typeof module === 'undefined') {
  document.addEventListener('DOMContentLoaded', initWizard);
}

// ─── Exports CommonJS para Jest ──────────────────────────────────────────────
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    goToStep: goToStep,
    saveProgress: saveProgress,
    restoreProgress: restoreProgress,
    clearProgress: clearProgress,
    validateCPF: validateCPF,
    validateAge: validateAge,
    validateStep: validateStep,
    clearFieldError: clearFieldError,
    toggleConditional: toggleConditional,
    collectFormData: collectFormData,
    submitForm: submitForm,
    fetchPreFill: fetchPreFill,
    initWizard: initWizard,
    maskCPF: maskCPF,
    maskPhone: maskPhone,
    maskCEP: maskCEP,
    fetchViaCEP: fetchViaCEP,
    collectStepData: collectStepData,
    buildStepPayload: buildStepPayload,
    submitStep: submitStep,
  };
}
