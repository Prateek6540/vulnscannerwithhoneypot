// result.js

// Using 'logs' variable directly from HTML
document.addEventListener("DOMContentLoaded", function () {
    const logContainer = document.getElementById("log-container");
    const resultSummary = document.getElementById("result-summary");
    const finalResult = document.getElementById("final-result");
    const spinner = document.getElementById("spinner");

    // Display logs in HTML
    logs.forEach((log, index) => {
        const logElement = document.createElement("p");
        logElement.textContent = log;
        logContainer.appendChild(logElement);
    });

    // Show final result and hide the spinner
    spinner.style.display = "none";
    resultSummary.style.display = "block";

    // Check vulnerability status and set the final result message
    if (vulnerabilityDetected === "true") {
        finalResult.textContent = `This website is vulnerable to SQL Injection (Database: ${dbType}).`;
    } else {
        finalResult.textContent = "This website is not vulnerable to SQL Injection.";
    }
});
