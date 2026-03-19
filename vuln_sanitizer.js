function vulnerableFilter(userInput) {
    let decoded;
    try {
        decoded = decodeURIComponent(userInput);
    } catch (e) {
        decoded = userInput;
    }
    
    const blockedPattern = /(javascript|vbscript|data):/i;
    if (blockedPattern.test(decoded)) {
        throw new Error("Blocked");
    }
    
    return decoded;
}

function vulnerableFilterHTMLEntity(userInput) {
    let decoded = userInput.replace(/&#x([0-9a-f]+);/gi, (match, hex) => 
        String.fromCharCode(parseInt(hex, 16))
    );
    
    const blockedPattern = /(javascript|vbscript|data):/i;
    if (blockedPattern.test(decoded)) {
        throw new Error("Blocked");
    }
    
    return decoded;
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = { vulnerableFilter, vulnerableFilterHTMLEntity };
}

if (typeof window !== 'undefined' || typeof process !== 'undefined') {
    console.log("=== Testing vulnerableFilter ===\n");
    
    const benign = "https://example.com";
    const maliciousURL = "java%0dscript:alert(1)";
    const maliciousNewline = "java%0ascript:alert(1)";
    const maliciousTab = "java%09script:alert(1)";
    
    try {
        const result1 = vulnerableFilter(benign);
        console.log(`Benign: ${result1}`);
    } catch (e) {
        console.log(`Blocked: ${e.message}`);
    }
    
    try {
        const result2 = vulnerableFilter(maliciousURL);
        console.log(`BYPASSED: ${JSON.stringify(result2)}`);
    } catch (e) {
        console.log(`Blocked: ${e.message}`);
    }
    
    try {
        const result3 = vulnerableFilter(maliciousNewline);
        console.log(`BYPASSED: ${JSON.stringify(result3)}`);
    } catch (e) {
        console.log(`Blocked: ${e.message}`);
    }
    
    try {
        const result4 = vulnerableFilter(maliciousTab);
        console.log(`BYPASSED: ${JSON.stringify(result4)}`);
    } catch (e) {
        console.log(`Blocked: ${e.message}`);
    }
    
    console.log("\n=== Testing vulnerableFilterHTMLEntity ===\n");
    
    const maliciousHTML = "java&#x0d;script:alert(1)";
    const maliciousHTMLNewline = "java&#x0ascript:alert(1)";
    
    try {
        const result5 = vulnerableFilterHTMLEntity(maliciousHTML);
        console.log(`BYPASSED: ${JSON.stringify(result5)}`);
    } catch (e) {
        console.log(`Blocked: ${e.message}`);
    }
    
    try {
        const result6 = vulnerableFilterHTMLEntity(maliciousHTMLNewline);
        console.log(`BYPASSED: ${JSON.stringify(result6)}`);
    } catch (e) {
        console.log(`Blocked: ${e.message}`);
    }
}
