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

    /* Decoded in chunks so a large file does not build one enormous array. */
    function base64ToBlob(b64) {
        var binary = atob(b64);
        var chunk = 0x8000;
        var parts = [];
        for (var offset = 0; offset < binary.length; offset += chunk) {
            var slice = binary.slice(offset, offset + chunk);
            var bytes = new Uint8Array(slice.length);
            for (var i = 0; i < slice.length; i++) bytes[i] = slice.charCodeAt(i);
            parts.push(bytes);
        }
        return new Blob(parts, { type: "application/octet-stream" });
    }

    /* Old object URLs are revoked so repeated runs do not pin memory. */
    function attachDownload(anchor, blob, filename) {
        if (anchor.dataset.url) URL.revokeObjectURL(anchor.dataset.url);
        var url = URL.createObjectURL(blob);
        anchor.dataset.url = url;
        anchor.href = url;
        anchor.download = filename;
    }

    function showStatus(el, message, kind) {
        el.className = "status status-" + kind;
        el.innerHTML = "";
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

    /* Errors always come back as JSON, whatever responseType was asked for. */
    function readError(body) {
        if (body instanceof Blob) {
            return body.text().then(function (text) {
                try { return JSON.parse(text); } catch (e) { return {}; }
            });
        }
        try { return Promise.resolve(JSON.parse(body)); } catch (e) { return Promise.resolve({}); }
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

    var algorithmCombo = initCombo($("algorithmCombo"), algorithm);
    var usePassphrase = false;

    function setMode(wantPassphrase) {
        var allowed = Boolean(algorithmCombo.selectedOption.dataset.supportsPassphrase);
        usePassphrase = wantPassphrase && allowed;

        modeKeyfile.classList.toggle("is-selected", !usePassphrase);
        modePassphrase.classList.toggle("is-selected", usePassphrase);
        modeKeyfile.setAttribute("aria-checked", usePassphrase ? "false" : "true");
        modePassphrase.setAttribute("aria-checked", usePassphrase ? "true" : "false");
        modePassphrase.disabled = !allowed;
        passphraseField.hidden = !usePassphrase;
        if (!usePassphrase) passphrase.value = "";

        $("modeHint").textContent = !allowed
            ? "This algorithm has no key for a passphrase to replace."
            : usePassphrase
                ? "One self-contained file. Nothing to store but the passphrase — " +
                  "and no way back without it."
                : "Two files: the encrypted one and a key file you must keep.";
    }

    modeKeyfile.addEventListener("click", function () { setMode(false); });
    modePassphrase.addEventListener("click", function () { setMode(true); });

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

        /* Re-evaluated because the new algorithm may not support passphrases. */
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

        var body = new FormData();
        body.append("file", encryptInput.files[0]);
        body.append("algorithm", algorithm.value);
        if (usePassphrase) body.append("passphrase", passphrase.value.trim());

        var wrap = $("encryptProgress");
        var bar = $("encryptProgressBar");

        encryptResult.hidden = true;
        resetProgress(wrap, bar);
        showStatus(encryptStatus, "Encrypting…", "info");
        busy(encryptForm, true, "Encrypting…");

        post("/encrypt", body, { onProgress: progressWriter(wrap, bar) })
            .then(function (result) {
                resetProgress(wrap, bar);
                if (!result.ok) {
                    return readError(result.body).then(function (data) {
                        showStatus(encryptStatus, data.error || "Encryption failed.", "error");
                    });
                }
                var data = JSON.parse(result.body);

                attachDownload($("downloadPayload"), base64ToBlob(data.encrypted.data),
                               data.encrypted.filename);
                $("payloadName").textContent = data.encrypted.filename;
                $("payloadSize").textContent = formatSize(data.encrypted.size);

                /* Passphrase mode returns one file and no key: the header rides
                 * inside the ciphertext, so there is nothing else to hand over. */
                var sealed = !data.key;
                $("downloadKey").hidden = sealed;
                $("keyfileNotice").hidden = sealed;
                $("passphraseNotice").hidden = !sealed;
                $("encryptDownloads").classList.toggle("downloads-single", sealed);
                if (!sealed) {
                    attachDownload($("downloadKey"), base64ToBlob(data.key.data),
                                   data.key.filename);
                    $("keyName").textContent = data.key.filename;
                    $("keySize").textContent = formatSize(data.key.size);
                }

                $("encryptResultMeta").textContent = data.lossy
                    ? data.algorithm_label + " — stacking the shares returns a " +
                      "black-and-white approximation, not the original file."
                    : data.algorithm_label + (sealed ? " · passphrase protected" : "");

                encryptStatus.hidden = true;
                encryptResult.hidden = false;
            })
            .catch(function (error) {
                resetProgress(wrap, bar);
                showStatus(encryptStatus, "Could not reach the server: " + error.message, "error");
            })
            .then(function () { busy(encryptForm, false); });
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

        var body = new FormData();
        body.append("file", payloadInput.files[0]);
        if (decryptMode === "passphrase") {
            body.append("passphrase", decryptPassphrase.value.trim());
        } else if (keyInput.files.length) {
            body.append("key_file", keyInput.files[0]);
        } else if (keyText.value.trim()) {
            body.append("key_text", keyText.value);
        }

        var wrap = $("decryptProgress");
        var bar = $("decryptProgressBar");

        decryptResult.hidden = true;
        resetProgress(wrap, bar);
        showStatus(decryptStatus, "Decrypting…", "info");
        busy(decryptForm, true, "Decrypting…");

        post("/decrypt", body, {
            responseType: "blob",
            onProgress: progressWriter(wrap, bar)
        })
            .then(function (result) {
                resetProgress(wrap, bar);
                /* Success streams the file back; failure arrives as JSON. */
                if (!result.ok) {
                    return readError(result.body).then(function (data) {
                        showStatus(decryptStatus, data.error || "Decryption failed.", "error");
                    });
                }
                var raw = result.header("X-Original-Filename");
                var name = "recovered";
                if (raw) {
                    try { name = decodeURIComponent(raw); } catch (e) { name = raw; }
                }

                attachDownload($("downloadPlain"), result.body, name);
                $("plainName").textContent = name;
                $("plainSize").textContent = formatSize(result.body.size);

                /* Say what actually happened rather than always claiming a
                 * checksum matched -- an envelope is MAC-checked, and visual
                 * crypto shares carry no checksum at all. */
                var verified = result.header("X-Verified") || "none";
                var meta = VERIFIED_TEXT[verified] || VERIFIED_TEXT.none;
                if (result.header("X-Lossy") === "1") {
                    meta = "Shares stacked. This is a black-and-white approximation at " +
                           "double size, not the original file.";
                }
                $("decryptResultMeta").textContent = meta;

                decryptStatus.hidden = true;
                decryptResult.hidden = false;
            })
            .catch(function (error) {
                resetProgress(wrap, bar);
                showStatus(decryptStatus, "Could not reach the server: " + error.message, "error");
            })
            .then(function () { busy(decryptForm, false); });
    });
})();
