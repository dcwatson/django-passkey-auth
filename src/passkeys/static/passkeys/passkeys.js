async function registerPasskey(endpoint, redirect) {
    const optionsResponse = await fetch(endpoint);
    var options = await optionsResponse.json();
    options.challenge = Uint8Array.from(options.challenge);
    options.user.id = Uint8Array.from(options.user.id);
    const creds = await navigator.credentials.create({
        publicKey: options,
    });
    const clientJSONBytes = new Uint8Array(creds.response.clientDataJSON);
    const keyBytes = new Uint8Array(creds.response.getPublicKey());
    const authBytes = new Uint8Array(creds.response.getAuthenticatorData());
    const passkeyData = {
        id: creds.id,
        algorithm: creds.response.getPublicKeyAlgorithm(),
        publicKeyDer: btoa(String.fromCharCode(...keyBytes)),
        clientData: btoa(String.fromCharCode(...clientJSONBytes)),
        authData: btoa(String.fromCharCode(...authBytes)),
    };
    const registerResponse = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(passkeyData),
    });
    const registerData = await registerResponse.json();
    if (registerData.success && redirect) window.location = redirect;
}

async function authenticatePasskey(endpoint, redirect) {
    const challengeResponse = await fetch(endpoint);
    const challengeData = await challengeResponse.json();
    const creds = await navigator.credentials.get({
        publicKey: {
            challenge: Uint8Array.from(challengeData.challenge),
        },
    });
    const jsonBytes = new Uint8Array(creds.response.clientDataJSON);
    const authBytes = new Uint8Array(creds.response.authenticatorData);
    const sigBytes = new Uint8Array(creds.response.signature);
    const userIdBytes = new Uint8Array(creds.response.userHandle);
    const loginData = {
        id: creds.id,
        clientData: btoa(String.fromCharCode(...jsonBytes)),
        authData: btoa(String.fromCharCode(...authBytes)),
        signature: btoa(String.fromCharCode(...sigBytes)),
        userId: btoa(String.fromCharCode(...userIdBytes)),
    };
    const loginResponse = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(loginData),
    });
    const responseData = await loginResponse.json();
    if (responseData.success && redirect) window.location = redirect;
}
