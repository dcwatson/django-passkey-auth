async function registerPasskey(endpoint, redirect) {
    const optionsResponse = await fetch(endpoint);
    const options = await optionsResponse.json();

    const creds = await navigator.credentials.create({
        publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options),
    });

    const registerResponse = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(creds),
    });

    const registerData = await registerResponse.json();
    if (registerData.success && redirect) window.location = redirect;
}

async function authenticatePasskey(endpoint, redirect, mediation = "optional") {
    const optionsResponse = await fetch(endpoint);
    const options = await optionsResponse.json();

    const creds = await navigator.credentials.get({
        publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options),
        mediation: mediation,
    });

    const loginResponse = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(creds),
    });

    const responseData = await loginResponse.json();
    if (responseData.success && redirect) window.location = redirect;
}

async function maybeAuthenticate(endpoint, redirect) {
    if (
        window.PublicKeyCredential &&
        PublicKeyCredential.isConditionalMediationAvailable
    ) {
        const cma = await PublicKeyCredential.isConditionalMediationAvailable();
        if (cma) {
            await authenticatePasskey(endpoint, redirect, "conditional");
        }
    }
}
