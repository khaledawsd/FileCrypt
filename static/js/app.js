/* The encrypt/decrypt tool.
 *
 * Moved out of index.html so it can be cached, linted, and served under a
 * Content-Security-Policy that does not have to allow inline script. Values
 * that used to come from Jinja now arrive on #appConfig instead. */
(function () {
    "use strict";

    var $ = function (id) { return document.getElementById(id); };

    var config = $("appConfig").dataset;
    var MAX_MB = config.maxMb;
    var MIN_PASSPHRASE = parseInt(config.minPassphrase, 10);

    /* First bytes of the two containers the decrypt panel can recognise: a
     * passphrase envelope (see utils/envelope.py) and a zip, which is what
     * visual cryptography emits. */
    var MAGIC_ENVELOPE = [0x46, 0x43, 0x50, 0x31];  /* "FCP1" */
    var MAGIC_ZIP = [0x50, 0x4b];                   /* "PK"   */

    function formatSize(bytes) {
        if (bytes < 1024) return bytes + " B";
        var units = ["KB", "MB", "GB"];
        var value = bytes / 1024;
        var i = 0;
        while (value >= 1024 && i < units.length - 1) { value /= 1024; i++; }
        return value.toFixed(value < 10 ? 1 : 0) + " " + units[i];
    }

    /* Old object URLs are revoked so repeated runs do not pin memory. */
    function attachDownload(anchor, blob, filename) {
        if (anchor.dataset.url) URL.revokeObjectURL(anchor.dataset.url);
        var url = URL.createObjectURL(blob);
        anchor.dataset.url = url;
        anchor.href = url;
        anchor.download = filename;
    }

    /* Single polite live region for both panels. Announcing from one place
     * keeps a screen reader from reading a result twice. */
    var announceTimer = null;

    function announce(message) {
        var region = $("announcer");
        region.textContent = "";
        /* Re-setting identical text is not a change, so nothing would be read;
         * clearing first and setting a tick later makes each message fresh.
         *
         * setTimeout rather than requestAnimationFrame: rAF does not fire at all
         * while the tab is hidden, so starting an encryption and switching away
         * would drop the announcement -- the moment it matters most. */
        clearTimeout(announceTimer);
        announceTimer = setTimeout(function () { region.textContent = message; }, 50);
    }

    function showStatus(el, message, kind) {
        el.className = "status status-" + kind;
        el.innerHTML = "";
        announce(message);
        if (kind === "info") {
            var svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
            svg.setAttribute("class", "icon spin");
            var use = document.createElementNS("http://www.w3.org/2000/svg", "use");
            use.setAttribute("href", "#i-loader");
            svg.appendChild(use);
            el.appendChild(svg);
        }
        el.appendChild(document.createTextNode(message));
        el.hidden = false;
    }

    function busy(form, isBusy, label) {
        var button = form.querySelector("button[type=submit]");
        button.disabled = isBusy;
        if (isBusy) {
            button.dataset.idle = button.innerHTML;
            button.innerHTML =
                '<svg class="icon spin"><use href="#i-loader"/></svg> ' + label;
        } else if (button.dataset.idle) {
            button.innerHTML = button.dataset.idle;
        }
    }

    /* ------------------------------------------------------------ upload */
    /* XMLHttpRequest rather than fetch: fetch cannot report upload progress,
     * and at the 32 MB ceiling a silent wait is a long one. */
    function post(url, body, options) {
        options = options || {};
        return new Promise(function (resolve, reject) {
            var xhr = new XMLHttpRequest();
            xhr.open("POST", url);
            xhr.responseType = options.responseType || "text";

            if (options.onProgress) {
                xhr.upload.addEventListener("progress", function (e) {
                    if (e.lengthComputable) options.onProgress(e.loaded / e.total);
                });
                xhr.upload.addEventListener("load", function () {
                    options.onProgress(1);
                });
            }
            xhr.addEventListener("load", function () {
                resolve({
                    ok: xhr.status >= 200 && xhr.status < 300,
                    status: xhr.status,
                    body: xhr.response,
                    header: function (name) { return xhr.getResponseHeader(name); }
                });
            });
            xhr.addEventListener("error", function () {
                reject(new Error("the connection failed"));
            });
            xhr.addEventListener("timeout", function () {
                reject(new Error("the request timed out"));
            });
            xhr.send(body);
        });
    }

    /* Errors always come back as JSON, whatever responseType was asked for --
     * so the body may be a Blob, an ArrayBuffer, or already text. */
    function readError(body) {
        var text;
        if (body instanceof Blob) {
            return body.text().then(function (decoded) {
                try { return JSON.parse(decoded); } catch (e) { return {}; }
            });
        }
        if (body instanceof ArrayBuffer) {
            text = new TextDecoder().decode(new Uint8Array(body));
        } else {
            text = body;
        }
        try { return Promise.resolve(JSON.parse(text)); } catch (e) { return Promise.resolve({}); }
    }

    function progressWriter(wrap, bar) {
        return function (fraction) {
            wrap.hidden = false;
            bar.style.width = Math.round(fraction * 100) + "%";
        };
    }

    function resetProgress(wrap, bar) {
        wrap.hidden = true;
        bar.style.width = "0%";
    }

    /* Read enough of a file to recognise its container. */
    function sniff(file) {
        return new Promise(function (resolve) {
            var reader = new FileReader();
            reader.onload = function (e) { resolve(new Uint8Array(e.target.result)); };
            reader.onerror = function () { resolve(new Uint8Array(0)); };
            reader.readAsArrayBuffer(file.slice(0, 4));
        });
    }

    function startsWith(bytes, magic) {
        if (bytes.length < magic.length) return false;
        for (var i = 0; i < magic.length; i++) {
            if (bytes[i] !== magic[i]) return false;
        }
        return true;
    }

    /* ------------------------------------------------------------ tabs */
    var panels = { encrypt: $("panel-encrypt"), decrypt: $("panel-decrypt") };
    var tabs = [$("tab-encrypt"), $("tab-decrypt")];
    tabs.forEach(function (tab) {
        tab.addEventListener("click", function () {
            var target = tab.id.replace("tab-", "");
            tabs.forEach(function (t) {
                t.setAttribute("aria-selected", t === tab ? "true" : "false");
            });
            Object.keys(panels).forEach(function (name) {
                panels[name].hidden = name !== target;
            });
        });
    });

    /* ------------------------------------------------------- dropzones */
    function wireDropZone(zone, input, onPick) {
        var open = function () { input.click(); };
        zone.addEventListener("click", open);
        zone.addEventListener("keydown", function (e) {
            if (e.key === "Enter" || e.key === " ") { e.preventDefault(); open(); }
        });
        ["dragenter", "dragover"].forEach(function (type) {
            zone.addEventListener(type, function (e) {
                e.preventDefault();
                zone.classList.add("is-over");
            });
        });
        ["dragleave", "drop"].forEach(function (type) {
            zone.addEventListener(type, function (e) {
                e.preventDefault();
                zone.classList.remove("is-over");
            });
        });
        zone.addEventListener("drop", function (e) {
            if (e.dataTransfer.files.length) {
                input.files = e.dataTransfer.files;
                onPick(e.dataTransfer.files[0]);
            }
        });
        input.addEventListener("change", function () {
            if (input.files.length) onPick(input.files[0]);
        });
    }

    function wireClear(button, input, row, after) {
        button.addEventListener("click", function () {
            input.value = "";
            row.hidden = true;
            if (after) after();
        });
    }

    /* ---------------------------------------------------- custom listbox */
    /* Stands in for a native <select>. Needed because the browser draws a
       native select's open-state colours itself -- on a dark page that means
       a jarring light system menu no amount of CSS here can reach. */
    function initCombo(root, hiddenInput) {
        var trigger = root.querySelector(".combo-trigger");
        var list = root.querySelector(".combo-list");
        var valueEl = root.querySelector(".combo-value");
        var options = Array.prototype.slice.call(list.querySelectorAll(".combo-option"));

        function indexOfValue(value) {
            for (var i = 0; i < options.length; i++) {
                if (options[i].dataset.value === value) return i;
            }
            return -1;
        }

        var activeIndex = Math.max(0, indexOfValue(hiddenInput.value));

        function setActive(index, opts) {
            opts = opts || {};
            activeIndex = (index + options.length) % options.length;
            options.forEach(function (opt, i) {
                opt.classList.toggle("is-active", i === activeIndex);
            });
            list.setAttribute("aria-activedescendant", options[activeIndex].id);
            if (opts.scroll !== false) {
                options[activeIndex].scrollIntoView({ block: "nearest" });
            }
        }

        function isOpen() { return root.dataset.open === "true"; }

        function open() {
            if (isOpen()) return;
            root.dataset.open = "true";
            list.hidden = false;
            trigger.setAttribute("aria-expanded", "true");
            setActive(Math.max(0, indexOfValue(hiddenInput.value)), { scroll: false });
            list.focus();
            document.addEventListener("click", onDocumentClick, true);
        }

        function close(opts) {
            opts = opts || {};
            if (!isOpen()) return;
            root.dataset.open = "false";
            list.hidden = true;
            trigger.setAttribute("aria-expanded", "false");
            document.removeEventListener("click", onDocumentClick, true);
            if (opts.focusTrigger !== false) trigger.focus();
        }

        function onDocumentClick(e) {
            if (!root.contains(e.target)) close({ focusTrigger: false });
        }

        function selectOption(opt) {
            options.forEach(function (o) {
                o.setAttribute("aria-selected", o === opt ? "true" : "false");
            });
            hiddenInput.value = opt.dataset.value;
            valueEl.textContent = opt.dataset.label;
            close();
            root.dispatchEvent(new CustomEvent("combo-change"));
        }

        trigger.addEventListener("click", function () {
            if (isOpen()) { close(); } else { open(); }
        });

        trigger.addEventListener("keydown", function (e) {
            if (e.key === "ArrowDown" || e.key === "ArrowUp" || e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                var wasOpen = isOpen();
                open();
                if (!wasOpen && e.key === "ArrowUp") setActive(activeIndex - 1);
            }
        });

        var typeahead = "";
        var typeaheadTimer = null;

        list.addEventListener("keydown", function (e) {
            switch (e.key) {
                case "ArrowDown":
                    e.preventDefault();
                    setActive(activeIndex + 1);
                    break;
                case "ArrowUp":
                    e.preventDefault();
                    setActive(activeIndex - 1);
                    break;
                case "Home":
                    e.preventDefault();
                    setActive(0);
                    break;
                case "End":
                    e.preventDefault();
                    setActive(options.length - 1);
                    break;
                case "Enter":
                case " ":
                    e.preventDefault();
                    selectOption(options[activeIndex]);
                    break;
                case "Escape":
                    e.preventDefault();
                    close();
                    break;
                case "Tab":
                    close({ focusTrigger: false });
                    break;
                default:
                    if (e.key.length === 1 && /[a-z0-9]/i.test(e.key)) {
                        typeahead += e.key.toLowerCase();
                        clearTimeout(typeaheadTimer);
                        typeaheadTimer = setTimeout(function () { typeahead = ""; }, 600);
                        for (var step = 1; step <= options.length; step++) {
                            var idx = (activeIndex + step) % options.length;
                            if (options[idx].dataset.label.toLowerCase().indexOf(typeahead) === 0) {
                                setActive(idx);
                                break;
                            }
                        }
                    }
            }
        });

        options.forEach(function (opt, i) {
            opt.addEventListener("click", function () { selectOption(opt); });
            opt.addEventListener("mousemove", function () {
                if (activeIndex !== i) setActive(i, { scroll: false });
            });
        });

        valueEl.textContent = options[activeIndex].dataset.label;

        return {
            get selectedOption() { return options[indexOfValue(hiddenInput.value)]; },
            onChange: function (fn) { root.addEventListener("combo-change", fn); }
        };
    }

    /* ------------------------------------------------- where work happens */
    /* AES is the only algorithm WebCrypto can do, and crypto.subtle exists only
     * in a secure context -- so over plain http to anything but localhost this
     * is false and everything falls back to the local Python process. */
    function localAvailable() {
        return window.FileCryptWeb && FileCryptWeb.available();
    }

    function localHandles(name) {
        return name === "aes" && localAvailable();
    }

    /* Mirrors routes.crypto.safe_name so a file encrypted in the browser is
     * named the same as one the Python side produced. */
    var UNSAFE_NAME_CHARS = "<>:\"/\\|?*";

    function safeName(name, fallback) {
        name = String(name || "").replace(/\\/g, "/");
        name = name.slice(name.lastIndexOf("/") + 1).trim();

        /* Character-by-character rather than a regex class: the set includes
         * every control character, and writing those as literals in the source
         * makes the file read as binary to grep and invites an editor to mangle
         * them. */
        var cleaned = "";
        for (var i = 0; i < name.length; i++) {
            if (UNSAFE_NAME_CHARS.indexOf(name.charAt(i)) === -1 &&
                name.charCodeAt(i) >= 32) {
                cleaned += name.charAt(i);
            }
        }
        cleaned = cleaned.replace(/^[. ]+|[. ]+$/g, "");
        return cleaned.slice(0, 120) || (fallback || "file");
    }

    function readFile(file) {
        return new Promise(function (resolve, reject) {
            var reader = new FileReader();
            reader.onload = function (e) { resolve(new Uint8Array(e.target.result)); };
            reader.onerror = function () { reject(new Error("could not read that file")); };
            reader.readAsArrayBuffer(file);
        });
    }

    function blobOf(bytes) {
        return new Blob([bytes], { type: "application/octet-stream" });
    }

    /* The success body is `uint32 key length | key JSON | ciphertext`. The
     * response used to be JSON with both halves base64-encoded, which held
     * about five copies of the upload in memory at the peak. */
    function unframe(buffer, result) {
        var bytes = new Uint8Array(buffer);
        if (bytes.length < 4) throw new Error("the app sent a truncated response");
        var keyLength = new DataView(buffer).getUint32(0, false);
        if (4 + keyLength > bytes.length) {
            throw new Error("the app sent a malformed response");
        }
        var header = function (name) {
            var value = result.header(name);
            if (!value) return null;
            try { return decodeURIComponent(value); } catch (e) { return value; }
        };
        return {
            payload: bytes.subarray(4 + keyLength),
            filename: header("X-Filename") || "encrypted.bin",
            keyBytes: keyLength ? bytes.subarray(4, 4 + keyLength) : null,
            keyFilename: keyLength ? header("X-Key-Filename") : null,
            algorithmLabel: header("X-Algorithm-Label") || "",
            lossy: result.header("X-Lossy") === "1",
            local: false
        };
    }

    /* --------------------------------------------------------- encrypt */
    var algorithm = $("algorithm");
    var encryptInput = $("encryptInput");
    var encryptForm = $("encryptForm");
    var encryptStatus = $("encryptStatus");
    var encryptResult = $("encryptResult");
    var passphrase = $("passphrase");
    var passphraseField = $("passphraseField");
    var modeKeyfile = $("modeKeyfile");
    var modePassphrase = $("modePassphrase");
    var useLocal = $("useLocal");
    var kdfInput = $("kdf");

    var algorithmCombo = initCombo($("algorithmCombo"), algorithm);
    var kdfCombo = initCombo($("kdfCombo"), kdfInput);
    var usePassphrase = false;

    /* Client-side encryption implies PBKDF2: WebCrypto has no scrypt and no
     * Argon2, and shipping a JS implementation of either would mean two
     * versions of the same primitive that could drift apart. */
    function effectiveKdf() {
        return localChosen() ? "pbkdf2" : kdfInput.value;
    }

    function localChosen() {
        return localHandles(algorithm.value) && useLocal.checked;
    }

    function refreshLocal() {
        var possible = localHandles(algorithm.value);
        $("localField").hidden = !possible && localAvailable();
        useLocal.disabled = !possible;
        if (!possible) useLocal.checked = false;

        $("localHint").textContent = possible
            ? "Encrypted here in the tab. No request is made; the Python process never sees it."
            : "";

        /* Saying "PBKDF2 is in use" is more honest than leaving a control that
         * looks live but is ignored. */
        var overridden = localChosen();
        $("kdfCombo").hidden = overridden;
        $("kdfHint").textContent = overridden
            ? "PBKDF2, because that is the only password KDF browsers offer natively. " +
              "Untick the box above to hand it to the local app and choose another."
            : "";

        if (!localAvailable() && window.isSecureContext === false) {
            $("localField").hidden = false;
            useLocal.checked = false;
            useLocal.disabled = true;
            $("localHint").textContent =
                "In-browser encryption needs a secure context (https, or localhost). " +
                "This page is on plain http, so the local app does the work.";
        }
    }

    function setMode(wantPassphrase) {
        var allowed = Boolean(algorithmCombo.selectedOption.dataset.supportsPassphrase);
        usePassphrase = wantPassphrase && allowed;

        modeKeyfile.classList.toggle("is-selected", !usePassphrase);
        modePassphrase.classList.toggle("is-selected", usePassphrase);
        modeKeyfile.setAttribute("aria-checked", usePassphrase ? "false" : "true");
        modePassphrase.setAttribute("aria-checked", usePassphrase ? "true" : "false");
        /* Roving tabindex: a radiogroup is one stop in the tab order, and the
         * arrow keys move within it. Leaving both focusable would make Tab
         * walk through the options, which is the listbox behaviour, not this. */
        modeKeyfile.tabIndex = usePassphrase ? -1 : 0;
        modePassphrase.tabIndex = usePassphrase ? 0 : -1;
        modePassphrase.disabled = !allowed;
        passphraseField.hidden = !usePassphrase;
        if (!usePassphrase) passphrase.value = "";

        $("modeHint").textContent = !allowed
            ? "This algorithm has no key for a passphrase to replace."
            : usePassphrase
                ? "One self-contained file. Nothing to store but the passphrase, " +
                  "and no way back without it."
                : "Two files: the encrypted one and a key file you must keep.";
        refreshLocal();
    }

    modeKeyfile.addEventListener("click", function () { setMode(false); });
    modePassphrase.addEventListener("click", function () { setMode(true); });
    useLocal.addEventListener("change", refreshLocal);
    kdfCombo.onChange(refreshLocal);

    /* role="radio" promises arrow-key navigation; without this the control
     * claims a keyboard interface it does not have. Selection follows focus,
     * which is the expected behaviour for a radio group. */
    [modeKeyfile, modePassphrase].forEach(function (button) {
        button.addEventListener("keydown", function (e) {
            var wantPassphrase;
            switch (e.key) {
                case "ArrowRight":
                case "ArrowDown":
                case "ArrowLeft":
                case "ArrowUp":
                    /* Two options, so any arrow simply toggles. */
                    wantPassphrase = button === modeKeyfile;
                    break;
                case "Home":
                    wantPassphrase = false;
                    break;
                case "End":
                    wantPassphrase = true;
                    break;
                default:
                    return;
            }
            e.preventDefault();
            setMode(wantPassphrase);
            (wantPassphrase ? modePassphrase : modeKeyfile).focus();
        });
    });

    function refreshAlgorithm() {
        var option = algorithmCombo.selectedOption;
        $("algorithmSummary").textContent = option.dataset.summary || "";

        var messages = [];
        if (option.dataset.educational) {
            messages.push(
                "This is a demonstration of the idea, not reviewed cryptography. It " +
                "round-trips your file faithfully, but do not rely on it to protect " +
                "anything that matters."
            );
        }
        if (option.dataset.notes) messages.push(option.dataset.notes);

        $("algorithmNotice").hidden = messages.length === 0;
        $("algorithmNoticeText").textContent = messages.join(" ");

        var imagesOnly = Boolean(option.dataset.imagesOnly);
        encryptInput.accept = imagesOnly ? "image/*" : "";
        $("encryptAccept").textContent = imagesOnly
            ? "Images only for this algorithm · up to " + MAX_MB + " MB"
            : "Any file type · up to " + MAX_MB + " MB";

        /* Re-evaluated because the new algorithm may not support passphrases,
         * and may not be one the browser can handle. */
        setMode(usePassphrase);
    }

    algorithmCombo.onChange(refreshAlgorithm);
    refreshAlgorithm();

    wireDropZone($("encryptDrop"), encryptInput, function (file) {
        $("encryptName").textContent = file.name;
        $("encryptSize").textContent = formatSize(file.size);
        $("encryptChosen").hidden = false;
        encryptStatus.hidden = true;
    });
    wireClear($("encryptClear"), encryptInput, $("encryptChosen"));

    function encryptLocally(file) {
        var name = safeName(file.name);
        return readFile(file).then(function (bytes) {
            if (!bytes.length) throw new Error("That file is empty.");
            if (usePassphrase) {
                return FileCryptWeb.encryptWithPassphrase(
                    bytes, name, passphrase.value.trim()
                ).then(function (sealed) {
                    return {
                        payload: sealed, filename: name + ".fcx",
                        keyBytes: null, keyFilename: null,
                        algorithmLabel: "AES-256-GCM", lossy: false, local: true
                    };
                });
            }
            return FileCryptWeb.encryptWithKeyFile(bytes, name).then(function (out) {
                return {
                    payload: out.payload, filename: name + ".enc",
                    keyBytes: new TextEncoder().encode(out.keyJson),
                    keyFilename: name + ".key.json",
                    algorithmLabel: "AES-256-GCM", lossy: false, local: true
                };
            });
        });
    }

    function encryptOnServer(file, onProgress) {
        var body = new FormData();
        body.append("file", file);
        body.append("algorithm", algorithm.value);
        if (usePassphrase) {
            body.append("passphrase", passphrase.value.trim());
            body.append("kdf", effectiveKdf());
        }
        return post("/encrypt", body, {
            responseType: "arraybuffer",
            onProgress: onProgress
        }).then(function (result) {
            if (!result.ok) {
                return readError(result.body).then(function (data) {
                    throw new Error(data.error || "Encryption failed.");
                });
            }
            return unframe(result.body, result);
        });
    }

    encryptForm.addEventListener("submit", function (event) {
        event.preventDefault();
        if (!encryptInput.files.length) {
            showStatus(encryptStatus, "Choose a file first.", "error");
            return;
        }
        if (usePassphrase && passphrase.value.trim().length < MIN_PASSPHRASE) {
            showStatus(
                encryptStatus,
                "Use a passphrase of at least " + MIN_PASSPHRASE + " characters.",
                "error"
            );
            passphrase.focus();
            return;
        }

        var file = encryptInput.files[0];
        var local = localChosen();
        var wrap = $("encryptProgress");
        var bar = $("encryptProgressBar");

        encryptResult.hidden = true;
        resetProgress(wrap, bar);
        showStatus(
            encryptStatus,
            local ? "Encrypting in your browser…" : "Encrypting…",
            "info"
        );
        busy(encryptForm, true, "Encrypting…");

        var work = local
            ? encryptLocally(file)
            : encryptOnServer(file, progressWriter(wrap, bar));

        work.then(function (out) {
            resetProgress(wrap, bar);

            attachDownload($("downloadPayload"), blobOf(out.payload), out.filename);
            $("payloadName").textContent = out.filename;
            $("payloadSize").textContent = formatSize(out.payload.length);

            /* Passphrase mode returns one file and no key: the header rides
             * inside the ciphertext, so there is nothing else to hand over. */
            var sealed = !out.keyBytes;
            $("downloadKey").hidden = sealed;
            $("keyfileNotice").hidden = sealed;
            $("passphraseNotice").hidden = !sealed;
            $("encryptDownloads").classList.toggle("downloads-single", sealed);
            if (!sealed) {
                attachDownload($("downloadKey"), blobOf(out.keyBytes), out.keyFilename);
                $("keyName").textContent = out.keyFilename;
                $("keySize").textContent = formatSize(out.keyBytes.length);
            }

            $("encryptResultMeta").textContent = out.lossy
                ? out.algorithmLabel + ": stacking the shares returns a " +
                  "black-and-white approximation, not the original file."
                : out.algorithmLabel + (sealed ? " · passphrase protected" : "");

            var where = $("encryptWhere");
            where.dataset.local = out.local ? "true" : "false";
            where.textContent = out.local
                ? "Encrypted in your browser. The file never left the tab."
                : "Encrypted by the app on this machine, then discarded.";

            encryptStatus.hidden = true;
            encryptResult.hidden = false;
            announce(
                "Encrypted " + (out.local ? "in your browser" : "by the local app") + ". " +
                (sealed
                    ? "One file ready to download: " + out.filename
                    : "Two files ready to download: " + out.filename +
                      " and " + out.keyFilename)
            );
        }).catch(function (error) {
            resetProgress(wrap, bar);
            showStatus(encryptStatus, error.message || "Encryption failed.", "error");
        }).then(function () { busy(encryptForm, false); });
    });

    /* --------------------------------------------------------- decrypt */
    var payloadInput = $("payloadInput");
    var keyInput = $("keyInput");
    var keyText = $("keyText");
    var decryptForm = $("decryptForm");
    var decryptStatus = $("decryptStatus");
    var decryptResult = $("decryptResult");
    var decryptPassphrase = $("decryptPassphrase");

    /* "keyfile" | "passphrase" | "shares" -- decided by the file's first bytes
     * so the panel asks for what this particular file needs and nothing else. */
    var decryptMode = "keyfile";

    function setDecryptMode(mode) {
        decryptMode = mode;
        $("decryptPassphraseField").hidden = mode !== "passphrase";
        $("noKeyNeeded").hidden = mode !== "shares";
        /* Hidden for an envelope, which cannot use a key file. Left in place for
         * shares: recognising a zip is a guess, and a wrong guess should not
         * strand someone whose ciphertext merely happens to start with "PK". */
        $("keyBlock").hidden = mode === "passphrase";
        if (mode === "passphrase") decryptPassphrase.focus();

        /* The form rearranges itself on file pick. Announce what it now wants,
         * or a screen reader user is left looking for a field that has gone. */
        announce({
            passphrase: "This file needs a passphrase. Key file not required.",
            shares: "Visual cryptography shares detected. No key required.",
            keyfile: "This file needs its key file."
        }[mode]);
    }

    $("keyHelpToggle").addEventListener("click", function () {
        $("keyHelp").hidden = !$("keyHelp").hidden;
    });

    wireDropZone($("payloadDrop"), payloadInput, function (file) {
        $("payloadChosenName").textContent = file.name;
        $("payloadChosenSize").textContent = formatSize(file.size);
        $("payloadChosen").hidden = false;
        decryptStatus.hidden = true;

        sniff(file).then(function (head) {
            if (startsWith(head, MAGIC_ENVELOPE)) {
                setDecryptMode("passphrase");
            } else if (startsWith(head, MAGIC_ZIP)) {
                setDecryptMode("shares");
            } else {
                setDecryptMode("keyfile");
            }
        });
    });
    wireClear($("payloadClear"), payloadInput, $("payloadChosen"), function () {
        setDecryptMode("keyfile");
    });

    function handleKeyFile(file) {
        $("keyChosenName").textContent = file.name;
        $("keyChosenSize").textContent = formatSize(file.size);
        $("keyChosen").hidden = false;
        decryptStatus.hidden = true;

        var reader = new FileReader();
        reader.onload = function (e) {
            keyText.value = e.target.result;
        };
        reader.readAsText(file);
    }

    wireDropZone($("keyDrop"), keyInput, handleKeyFile);
    wireClear($("keyClear"), keyInput, $("keyChosen"));

    /* Support dragging and dropping key file directly onto keyText textarea */
    ["dragenter", "dragover"].forEach(function (type) {
        keyText.addEventListener(type, function (e) {
            e.preventDefault();
            keyText.classList.add("is-over");
        });
    });
    ["dragleave", "drop"].forEach(function (type) {
        keyText.addEventListener(type, function (e) {
            e.preventDefault();
            keyText.classList.remove("is-over");
        });
    });
    keyText.addEventListener("drop", function (e) {
        if (e.dataTransfer.files.length) {
            keyInput.files = e.dataTransfer.files;
            handleKeyFile(e.dataTransfer.files[0]);
        }
    });

    var VERIFIED_TEXT = {
        mac: "Passphrase verified and the file was unmodified.",
        checksum: "Checksum matched the key file.",
        none: "Recovered. No checksum was stored for this file, so nothing was verified."
    };

    /* Try the browser first, but only when it can actually finish the job: AES,
     * and for an envelope a KDF WebCrypto has. Anything else -- scrypt, Argon2,
     * another algorithm -- returns null and it goes to the local app. */
    function decryptLocally(file) {
        if (!localAvailable()) return Promise.resolve(null);

        return readFile(file).then(function (bytes) {
            if (decryptMode === "passphrase") {
                if (!FileCryptWeb.canOpenEnvelope(bytes)) return null;
                return FileCryptWeb.decryptWithPassphrase(
                    bytes, decryptPassphrase.value.trim()
                ).then(function (out) {
                    return {
                        plaintext: out.plaintext,
                        filename: safeName(out.filename, "recovered"),
                        verified: out.verified, lossy: false, local: true
                    };
                });
            }

            if (decryptMode !== "keyfile" || !keyText.value.trim()) return null;
            var doc = FileCryptWeb.parseKeyFile(keyText.value);
            if (!FileCryptWeb.canOpenKeyFile(doc)) return null;
            return FileCryptWeb.decryptWithKeyFile(bytes, doc).then(function (out) {
                return {
                    plaintext: out.plaintext,
                    filename: safeName(doc.original_filename, "recovered"),
                    verified: out.verified, lossy: false, local: true
                };
            });
        });
    }

    function decryptOnServer(file, onProgress) {
        var body = new FormData();
        body.append("file", file);
        if (decryptMode === "passphrase") {
            body.append("passphrase", decryptPassphrase.value.trim());
        } else if (keyInput.files.length) {
            body.append("key_file", keyInput.files[0]);
        } else if (keyText.value.trim()) {
            body.append("key_text", keyText.value);
        }

        return post("/decrypt", body, {
            responseType: "blob",
            onProgress: onProgress
        }).then(function (result) {
            if (!result.ok) {
                return readError(result.body).then(function (data) {
                    throw new Error(data.error || "Decryption failed.");
                });
            }
            var raw = result.header("X-Original-Filename");
            var name = "recovered";
            if (raw) {
                try { name = decodeURIComponent(raw); } catch (e) { name = raw; }
            }
            return {
                plaintext: result.body,          // a Blob, which is fine here
                filename: name,
                verified: result.header("X-Verified") || "none",
                lossy: result.header("X-Lossy") === "1",
                local: false
            };
        });
    }

    decryptForm.addEventListener("submit", function (event) {
        event.preventDefault();

        if (!payloadInput.files.length) {
            showStatus(decryptStatus, "Choose the encrypted file.", "error");
            return;
        }
        if (decryptMode === "passphrase" && !decryptPassphrase.value.trim()) {
            showStatus(decryptStatus, "This file needs the passphrase it was encrypted with.", "error");
            decryptPassphrase.focus();
            return;
        }
        var hasKey = keyInput.files.length || keyText.value.trim();
        if (decryptMode === "keyfile" && !hasKey) {
            showStatus(decryptStatus, "Paste your key, or upload the .key.json file.", "error");
            return;
        }

        var file = payloadInput.files[0];
        var wrap = $("decryptProgress");
        var bar = $("decryptProgressBar");

        decryptResult.hidden = true;
        resetProgress(wrap, bar);
        showStatus(decryptStatus, "Decrypting…", "info");
        busy(decryptForm, true, "Decrypting…");

        decryptLocally(file).catch(function (error) {
            /* A local attempt that got far enough to fail on the passphrase or
             * the checksum is a real answer, not a reason to retry on the
             * local app -- re-sending would hand over a file the user believes
             * never left the tab. */
            throw error;
        }).then(function (out) {
            if (out) return out;
            return decryptOnServer(file, progressWriter(wrap, bar));
        }).then(function (out) {
            resetProgress(wrap, bar);

            var blob = out.plaintext instanceof Blob ? out.plaintext : blobOf(out.plaintext);
            attachDownload($("downloadPlain"), blob, out.filename);
            $("plainName").textContent = out.filename;
            $("plainSize").textContent = formatSize(blob.size);

            /* Say what actually happened rather than always claiming a
             * checksum matched -- an envelope is MAC-checked, and visual
             * crypto shares carry no checksum at all. */
            var meta = VERIFIED_TEXT[out.verified] || VERIFIED_TEXT.none;
            if (out.lossy) {
                meta = "Shares stacked. This is a black-and-white approximation at " +
                       "double size, not the original file.";
            }
            $("decryptResultMeta").textContent = meta;

            var where = $("decryptWhere");
            where.dataset.local = out.local ? "true" : "false";
            where.textContent = out.local
                ? "Decrypted in your browser. The file never left the tab."
                : "Decrypted by the app on this machine, then discarded.";

            decryptStatus.hidden = true;
            decryptResult.hidden = false;
            announce("Recovered " + out.filename + ". " + meta);
        }).catch(function (error) {
            resetProgress(wrap, bar);
            showStatus(decryptStatus, error.message || "Decryption failed.", "error");
        }).then(function () { busy(decryptForm, false); });
    });
})();
