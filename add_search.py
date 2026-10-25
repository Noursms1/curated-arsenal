import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INDEX_FILE = os.path.join(BASE_DIR, "templates", "index.html")
CSS_FILE = os.path.join(BASE_DIR, "static", "css", "style.css")

# 1. Update index.html
index_html = r"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Curated Arsenal | Security Tools</title>
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <header>
        <h1>⚔️ Curated Arsenal</h1>
        <p>Production-ready security tools, reviewed and refined.</p>
        
        <!-- Search Bar -->
        <div class="search-container">
            <input type="text" id="searchInput" placeholder="🔍 Search tools (e.g., dns, subdomain, port, crtsh)..." onkeyup="filterTools()">
        </div>
    </header>
    
    <main>
        <div class="grid" id="toolsGrid">
            {% for tool in tools %}
            <a href="/tool/{{ tool.id }}" class="card" data-name="{{ tool.name | lower }}" data-desc="{{ tool.description | lower }}" data-tags="{{ tool.tags | join(' ') | lower }}">
                <h2>{{ tool.name }}</h2>
                <span class="category">{{ tool.category }}</span>
                <p>{{ tool.description }}</p>
                <div class="tags">
                    {% for tag in tool.tags %}
                    <span class="tag">{{ tag }}</span>
                    {% endfor %}
                </div>
            </a>
            {% endfor %}
        </div>
        
        <!-- No Results Message -->
        <div id="noResults" style="display: none; text-align: center; margin-top: 40px; color: #8b949e;">
            <h2>No tools found matching your search.</h2>
            <p>Try different keywords.</p>
        </div>
    </main>

    <script>
        function filterTools() {
            const input = document.getElementById('searchInput').value.toLowerCase();
            const cards = document.querySelectorAll('.card');
            const noResults = document.getElementById('noResults');
            let visibleCount = 0;

            cards.forEach(card => {
                const name = card.getAttribute('data-name');
                const desc = card.getAttribute('data-desc');
                const tags = card.getAttribute('data-tags');

                if (name.includes(input) || desc.includes(input) || tags.includes(input)) {
                    card.style.display = 'block';
                    visibleCount++;
                } else {
                    card.style.display = 'none';
                }
            });

            if (visibleCount === 0 && input !== "") {
                noResults.style.display = 'block';
            } else {
                noResults.style.display = 'none';
            }
        }
    </script>
</body>
</html>
"""

with open(INDEX_FILE, "w", encoding="utf-8") as f:
    f.write(index_html)

# 2. Append Search Bar CSS
css_addition = r"""

/* Search Bar Styles */
.search-container {
    margin-top: 20px;
    display: flex;
    justify-content: center;
}

#searchInput {
    width: 60%;
    max-width: 600px;
    padding: 12px 20px;
    background-color: var(--card-bg);
    border: 1px solid var(--border);
    border-radius: 30px;
    color: var(--text);
    font-size: 16px;
    outline: none;
    transition: all 0.3s ease;
}

#searchInput:focus {
    border-color: var(--accent);
    box-shadow: 0 0 10px rgba(0, 255, 204, 0.2);
}

#searchInput::placeholder {
    color: #8b949e;
}
"""

with open(CSS_FILE, "a", encoding="utf-8") as f:
    f.write(css_addition)

print("[+] Search bar added successfully!")