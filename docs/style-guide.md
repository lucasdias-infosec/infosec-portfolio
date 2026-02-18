# Style Guide

This guide details writing standards, formatting, naming conventions, and best practices to maintain consistent, clear, and secure documentation.

## 1. Document Structure and Organization

**Title Hierarchy:**

# → Document Title

## → Main Sections

### → Sub-sections

#### → Detailed Topics

**Paragraphs:** Prefer 3–5 lines; break text to improve readability.

**Lists:** Use `-` or `*` consistently; numbered lists only for sequential steps.

**References:** Cite external sources concisely at the end of the document.

## 2. Code and Commands

- Always use code blocks (```) with specified language (bash, yaml, python).  
- Never include real network data, passwords, or private keys.  
- Prefer generic examples:
```bash
ssh user@host.example
```
- Use comments within code to explain complex parts.

## 3. Images and Media

- Store in `docs/assets/` with clear names (e.g., `topology-red-blue.png`).  
- Avoid screenshots of real systems or sensitive information.  
- Standardize size and aspect ratio when possible (e.g., max width 800px).  
- Short, descriptive captions to contextualize images.  

## 4. Terminology and Language

- Use accurate and consistent technical terms.  
- Use English for global concepts (e.g., SIEM, IDS) but explain in Portuguese if necessary.  
- Avoid unexplained jargon or abbreviations.  
- Maintain clear, objective, and neutral language.  

## 5. Markdown Standardization

- **Code:** Blocks with specified language.  
- **Internal links:** Use relative paths.  
- **Emphasis:** Bold for alerts or important terms; italic for examples or notes.  
- **Tables:** Organize data consistently with clear headers.  

## 6. Review and Pull Requests

- Check spelling, grammar, and style before the PR.  
- Include a clear description of changes and the purpose.  
- Ensure branch follows naming standard: `firstname-lastname/feature` or `feature/name`.  
- PR must be reviewed by at least one collaborator before merge.  

## 7. Security Best Practices

- All content must follow ethics and infosec best practices.  
- Never submit real client, network, or system data.  
- Any attack examples must be simulated in a safe environment.  
