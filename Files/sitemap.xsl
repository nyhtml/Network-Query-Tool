<?xml version="1.0" encoding="UTF-8"?>

<xsl:stylesheet
    version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:s="https://www.sitemaps.org/schemas/sitemap/0.9">

    <xsl:output method="html" encoding="UTF-8"/>

    <xsl:template match="/">
        <html>
            <head>
                <title>XML Sitemap</title>

                <style>
                    :root {
                        /* Light mode */
                        --bg: #f5f7fb;
                        --card: #ffffff;
                        --text: #222;
                        --muted: #667085;
                        --accent: #0ea5e9;
                        --accent-dark: #0369a1;

                        --radius: 14px;
                        --radius-sm: 10px;
                        --shadow: 0 2px 6px rgba(0,0,0,0.08);
                        --shadow-lg: 0 4px 12px rgba(0,0,0,0.10);
                    }

                    @media (prefers-color-scheme: dark) {
                        :root {
                            --bg: #0b0f14;
                            --card: #111827;
                            --text: #e5e7eb;
                            --muted: #9ca3af;
                            --accent: #0ea5e9;
                            --accent-dark: #0369a1;

                            --shadow: 0 2px 6px rgba(0,0,0,0.35);
                            --shadow-lg: 0 4px 12px rgba(0,0,0,0.45);
                        }
                    }

                    body {
                        font-family: system-ui, sans-serif;
                        margin: 40px;
                        background: var(--bg);
                        color: var(--text);
                    }

                    /* Snapshot-style title bar */
                    .card-title {
                        background: var(--card);
                        padding: 18px 22px;
                        border-radius: var(--radius);
                        box-shadow: var(--shadow-lg);
                        font-size: 22px;
                        font-weight: 600;
                        margin-bottom: 25px;
                    }

                    /* Snapshot-style footer */
                    .footer {
                        margin-top: 40px;
                        padding: 20px;
                        text-align: center;
                        color: var(--muted);
                        font-size: 14px;
                    }

                    /* Responsive wrapper */
                    .table-wrapper {
                        background: var(--card);
                        border-radius: var(--radius);
                        box-shadow: var(--shadow);
                        overflow-x: auto;
                        padding: 0;
                    }

                    table {
                        width: 100%;
                        border-collapse: collapse;
                        border-radius: var(--radius);
                        overflow: hidden;
                    }

                    thead th {
                        position: sticky;
                        top: 0;
                        background: var(--accent);
                        color: #fff;
                        padding: 16px;
                        font-size: 15px;
                        z-index: 5;
                    }

                    /* Rounded header corners */
                    thead th:first-child {
                        border-top-left-radius: var(--radius);
                    }
                    thead th:last-child {
                        border-top-right-radius: var(--radius);
                    }

                    th, td {
                        padding: 14px;
                        border-bottom: 1px solid var(--muted);
                        text-align: left;
                        font-size: 15px;
                    }

                    /* Subtle row separators */
                    tbody tr:not(:last-child) td {
                        border-bottom: 1px solid var(--muted);
                    }

                    /* Hover rows */
                    tbody tr:hover {
                        background: rgba(14,165,233,0.08);
                    }

                    a {
                        color: var(--accent-dark);
                        text-decoration: none;
                        font-weight: 500;
                    }

                    a:hover {
                        text-decoration: underline;
                    }

                    /* Compact mobile mode */
                    @media (max-width: 600px) {
                        body {
                            margin: 20px;
                        }

                        .card-title {
                            padding: 14px 16px;
                            font-size: 18px;
                        }

                        th, td {
                            padding: 10px;
                            font-size: 14px;
                        }
                    }
                </style>
            </head>

            <body>

                <div class="card-title">XML Sitemap Index</div>

                <p>
                    <xsl:value-of select="count(s:urlset/s:url)"/>
                    URLs found
                </p>

                <div class="table-wrapper">
                    <table>
                        <thead>
                            <tr>
                                <th>URL</th>
                                <th>Last modified (GMT)</th>
                            </tr>
                        </thead>

                        <tbody>

                            <xsl:for-each select="s:urlset/s:url">

                                <tr>
                                    <td>
                                        <a href="{s:loc}">
                                            <xsl:value-of select="s:loc"/>
                                        </a>
                                    </td>

                                    <td>
                                        <xsl:value-of select="s:lastmod"/>
                                    </td>
                                </tr>

                            </xsl:for-each>

                        </tbody>
                    </table>
                </div>

                <div class="footer">
                    Generated Automatically with <a title="Sipylus AI" target="_blank" href="http://ai.sipylus.com">Sipylus AI</a>
                </div>

            </body>
        </html>
    </xsl:template>

</xsl:stylesheet>
