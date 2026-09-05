const scanButton = document.querySelector("#scan-button");
const status = document.querySelector("#status");
const results = document.querySelector("#results");
const resultCount = document.querySelector("#result-count");
const findingList = document.querySelector("#finding-list");

scanButton.addEventListener("click", async () => {
  setLoading(true);
  try {
    const response = await chrome.runtime.sendMessage({ type: "SCAN_CURRENT_TAB" });
    if (!response?.ok) throw new Error(response?.error || "The scan could not be completed.");
    renderResults(response.bugs || []);
    status.textContent = response.usedMockData
      ? "Showing local mock findings. Start the API to analyze page data."
      : "Scan complete.";
  } catch (error) {
    status.textContent = error.message;
  } finally {
    setLoading(false);
  }
});

function setLoading(isLoading) {
  scanButton.disabled = isLoading;
  scanButton.textContent = isLoading ? "Scanning…" : "Scan Current Page";
  if (isLoading) status.textContent = "Collecting page context…";
}

function renderResults(bugs) {
  results.hidden = false;
  resultCount.textContent = `${bugs.length} found`;
  findingList.replaceChildren(...bugs.map(createFinding));
}

function createFinding(bug) {
  const card = document.createElement("article");
  card.className = "finding";

  const meta = document.createElement("div");
  meta.className = "finding-meta";
  meta.innerHTML = `<span class="category"></span><span class="severity"></span>`;
  meta.querySelector(".category").textContent = bug.category || "General";
  const severity = meta.querySelector(".severity");
  const severityName = (bug.severity || "low").toLowerCase();
  severity.classList.add(`severity-${severityName}`);
  severity.textContent = severityName;

  const title = document.createElement("h3");
  title.textContent = bug.title;
  const description = document.createElement("p");
  description.textContent = bug.description;
  const copyButton = document.createElement("button");
  copyButton.className = "copy-button";
  copyButton.type = "button";
  copyButton.textContent = "Copy Remediation Prompt";
  copyButton.addEventListener("click", async () => {
    await navigator.clipboard.writeText(bug.remediation_prompt || fallbackPrompt(bug));
    copyButton.textContent = "Copied";
    setTimeout(() => { copyButton.textContent = "Copy Remediation Prompt"; }, 1500);
  });

  card.append(meta, title, description, copyButton);
  return card;
}

function fallbackPrompt(bug) {
  return `Role: Senior Web Developer\n\nTask: Resolve ${bug.title}.\n\nContext: ${bug.description}\n\nRequirements:\n- Preserve existing behavior.\n- Add a regression test.\n- Explain the security and accessibility impact of the fix.`;
}
