document.addEventListener("DOMContentLoaded", function() {
    let currentStep = 0;

    // Get data from Flask
    const sqliDetected = "{{ 'Yes' if sqli_detected[0] == 'True' else 'No' }}";
    const dbType = "{{ db[0] if db else 'Unknown' }}";
    const riskLevel = "{{ risk_state[0] if risk_state else 'Unknown' }}";
    const formAction = "{{ form_list[0].action if form_list else 'No forms found' }}";

    // Elements for results display
    const sqliStatusElem = document.getElementById("sqli-status");
    const dbTypeElem = document.getElementById("database-type");
    const riskLevelElem = document.getElementById("risk-level");
    const htmlCodeElem = document.getElementById("html-code");
    const spinnerElem = document.getElementById("spinner");

    // Elements for smooth transition display
    const vulnerabilitySection = document.querySelector('.vulnerability');
    const htmlSection = document.querySelector('.html-output');

    const steps = [
        { // Step 1: Show SQL Injection detection status
            element: sqliStatusElem,
            content: `SQL Injection Detected: ${sqliDetected}`,
        },
        { // Step 2: Show database type
            element: dbTypeElem,
            content: `Database Type: ${dbType}`,
        },
        { // Step 3: Show risk level
            element: riskLevelElem,
            content: `Risk Level: ${riskLevel}`,
        },
        { // Step 4: Show HTML code for the form (if any)
            element: htmlCodeElem,
            content: `[+] HTML Form for Vulnerable Endpoint: ${formAction}`,
        }
    ];

    // Function to display each result one by one
    function showNextStep() {
        if (currentStep < steps.length) {
            const step = steps[currentStep];
            const element = step.element;
            const content = step.content;

            element.innerText = content;
            element.style.display = "block"; // Show the element

            currentStep++;
            setTimeout(showNextStep, 3000); // Delay before showing next step
        } else {
            // Hide spinner and show results sections after all steps are done
            spinnerElem.style.display = "none";
            vulnerabilitySection.style.display = "block";
            htmlSection.style.display = "block";
        }
    }

    // Start showing the steps
    setTimeout(() => {
        showNextStep();
    }, 1000); // Initial delay before showing results
});
