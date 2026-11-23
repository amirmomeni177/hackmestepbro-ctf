const traceCases = {
  baseline: { value: 'NamedNodeMap', length: '3', index: '2', handlers: '0' },
  incident: { value: 'HTMLInputElement', length: 'undefined', index: 'NaN', handlers: '2' },
};
const traceFields = Object.keys(traceCases.baseline);

for (const radio of document.querySelectorAll('input[name="trace"]')) {
  radio.addEventListener('change', () => {
    if (!radio.checked) return;
    for (const field of traceFields) {
      document.getElementById(`trace-${field}`).textContent = traceCases[radio.value][field];
    }
  });
}

const finding = document.getElementById('shadow-finding');
const submit = finding.querySelector('button');
const status = document.getElementById('shadow-status');
const solved = document.getElementById('shadow-solved');
const flag = document.getElementById('shadow-flag');

finding.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (submit.disabled) return;

  submit.disabled = true;
  status.textContent = 'Checking your finding…';
  solved.hidden = true;

  try {
    const response = await fetch('/api/shadowed-attributes/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(Object.fromEntries(new FormData(finding))),
    });
    if (!response.ok) throw new Error(`Verification returned ${response.status}`);
    const result = await response.json();
    if (!result.solved) {
      status.textContent = result.message;
      return;
    }

    flag.textContent = result.flag;
    solved.hidden = false;
    status.textContent = 'Finding accepted. Your flag is shown below.';
    try {
      localStorage.setItem('ctf:solved:shadowed-attributes', '1');
    } catch {
      // The flag remains visible when browser storage is unavailable.
    }
  } catch {
    status.textContent = 'Verification is temporarily unavailable. Try again.';
  } finally {
    submit.disabled = false;
  }
});
