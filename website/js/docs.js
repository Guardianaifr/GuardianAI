document.addEventListener("DOMContentLoaded", () => {
  // 1. Mobile Sidebar Toggle
  const sidebarToggle = document.getElementById("docs-sidebar-toggle");
  const sidebar = document.getElementById("docs-sidebar");
  if (sidebarToggle && sidebar) {
    sidebarToggle.addEventListener("click", () => {
      sidebar.classList.toggle("open");
    });
    // Close sidebar on link click (mobile)
    sidebar.addEventListener("click", (e) => {
      if (e.target.tagName.toLowerCase() === 'a' && window.innerWidth <= 800) {
        sidebar.classList.remove("open");
      }
    });
  }

  // 2. Code Tabs Switcher
  document.querySelectorAll(".docs-tabs").forEach((tabsContainer) => {
    const tabs = tabsContainer.querySelectorAll(".docs-tab");
    const codeBox = tabsContainer.closest(".docs-code-box");
    const blocks = codeBox.querySelectorAll(".docs-code-block");

    tabs.forEach((tab, index) => {
      tab.addEventListener("click", () => {
        tabs.forEach((t) => t.classList.remove("active"));
        blocks.forEach((b) => (b.style.display = "none"));

        tab.classList.add("active");
        if (blocks[index]) {
          blocks[index].style.display = "block";
        }
      });
    });
  });

  // 3. Copy Code Button
  document.querySelectorAll(".docs-copy-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const codeBox = btn.closest(".docs-code-box");
      const activeBlock =
        Array.from(codeBox.querySelectorAll(".docs-code-block")).find(
          (b) => b.style.display !== "none"
        ) || codeBox.querySelector(".docs-code-block");
      if (activeBlock) {
        navigator.clipboard.writeText(activeBlock.innerText.trim()).then(() => {
          const original = btn.innerText;
          btn.innerText = "Copied! ?";
          setTimeout(() => (btn.innerText = original), 2000);
        });
      }
    });
  });

  // 4. ScrollSpy for TOC & Left Nav
  const sections = document.querySelectorAll(".docs-section");
  const tocLinks = document.querySelectorAll(".docs-toc-list a");
  const sidebarLinks = document.querySelectorAll(".docs-nav-links a");

  function onScroll() {
    let current = "";
    sections.forEach((section) => {
      const top = section.offsetTop - 120;
      if (window.pageYOffset >= top) {
        current = section.getAttribute("id");
      }
    });

    if (current) {
      tocLinks.forEach((link) => {
        link.classList.remove("active");
        if (link.getAttribute("href") === `#${current}`) {
          link.classList.add("active");
        }
      });

      sidebarLinks.forEach((link) => {
        if (link.getAttribute("href") === `#${current}`) {
          link.classList.add("active");
        } else if (link.getAttribute("href").startsWith("#")) {
          link.classList.remove("active");
        }
      });
    }
  }

  window.addEventListener("scroll", onScroll);
  onScroll();

  // 5. Search Modal Logic
  const searchBtn = document.getElementById("docs-search-btn");
  const searchModal = document.getElementById("docs-search-modal");
  const searchInput = document.getElementById("docs-search-input");
  const searchResults = document.getElementById("docs-search-results");

  const searchIndex = [
    { title: "Quickstart & 5-Min Setup", url: "#quickstart", snippet: "Install guardianai SDK and wrap your LLM or LangChain agents." },
    { title: "System Architecture & Dual-Plane", url: "#architecture", snippet: "Off-chain millisecond prompt filtering combined with on-chain trust anchoring." },
    { title: "10-Layer AI Firewall", url: "#firewall", snippet: "Fast-path regex, entropy anomaly, semantic classifier, de-obfuscation and policy checks." },
    { title: "Output & DLP Scanner", url: "#dlp-scanner", snippet: "Scans model completions for private keys, seed phrases, API credentials and PII." },
    { title: "ERC-8004 Agent Registries", url: "#erc8004", snippet: "On-chain decentralized identity and permission registry on Monad." },
    { title: "Merkle Cortex Anchoring", url: "#cortex-anchoring", snippet: "Cryptographic state anchoring with verifiable Merkle tree root hashes." },
    { title: "Insurance Ledger & Certificates", url: "#insurance-certificates", snippet: "Cryptographic insurance certificate anchoring for automated agent verification." },
    { title: "Smart Contract Static Analyzer", url: "#contract-analyzer", snippet: "48 automated AST-validated vulnerability detection rules for EVM contracts." },
    { title: "Python SDK Reference", url: "#python-sdk", snippet: "Client library for Python 3.10+ with OpenAI, Anthropic, and LangChain support." },
    { title: "Proxy Gateway API (/v1/chat/completions)", url: "#proxy-api", snippet: "OpenAI-compatible reverse proxy endpoint with automated ingress inspection." },
    { title: "Telemetry & WebSocket Threat Stream", url: "#telemetry-api", snippet: "Real-time SIEM event export, JSON/CSV dumps, and /ws/threats live feed." },
    { title: "EU AI Act & Article 15 Compliance", url: "#compliance", snippet: "Automated technical evidence generation for AI governance and regulatory compliance." }
  ];

  function openSearch() {
    if (searchModal) {
      searchModal.classList.add("open");
      if (searchInput) {
        searchInput.value = "";
        searchInput.focus();
        renderResults("");
      }
    }
  }

  function closeSearch() {
    if (searchModal) searchModal.classList.remove("open");
  }

  function renderResults(query) {
    if (!searchResults) return;
    const q = query.toLowerCase().trim();
    const filtered = q
      ? searchIndex.filter(
          (item) =>
            item.title.toLowerCase().includes(q) ||
            item.snippet.toLowerCase().includes(q)
        )
      : searchIndex.slice(0, 6);

    searchResults.innerHTML = filtered.length
      ? filtered
          .map(
            (item) => `
        <li class="docs-search-item">
          <a href="${item.url}">
            <h5>${item.title}</h5>
            <p>${item.snippet}</p>
          </a>
        </li>
      `
          )
          .join("")
      : `<li style="padding:16px; color:#64748b; font-size:0.9rem;">No results found for "${query}"</li>`;

    searchResults.querySelectorAll("a").forEach((link) => {
      link.addEventListener("click", () => closeSearch());
    });
  }

  if (searchBtn) searchBtn.addEventListener("click", openSearch);

  if (searchModal) {
    searchModal.addEventListener("click", (e) => {
      if (e.target === searchModal) closeSearch();
    });
  }

  if (searchInput) {
    searchInput.addEventListener("input", (e) => renderResults(e.target.value));
  }

  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
      e.preventDefault();
      openSearch();
    }
    if (e.key === "Escape") closeSearch();
  });
});
