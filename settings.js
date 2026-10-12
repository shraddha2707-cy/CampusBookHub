(function () {
    const style = document.createElement('style');
    style.textContent = `
        .logout-backdrop {
            position: fixed;
            inset: 0;
            z-index: 10000;
            display: grid;
            place-items: center;
            padding: 20px;
            background: rgba(18, 32, 68, 0.48);
        }
        .logout-dialog {
            width: min(100%, 420px);
            padding: 28px;
            border-radius: 16px;
            background: #fff;
            color: #122044;
            box-shadow: 0 20px 60px rgba(18, 32, 68, 0.24);
            font-family: inherit;
        }
        .logout-dialog h2 {
            margin: 0 0 10px;
            font-size: 20px;
        }
        .logout-dialog p {
            margin: 0 0 24px;
            color: #60708d;
            font-size: 14px;
        }
        .logout-error {
            margin: -12px 0 18px !important;
            color: #b42318 !important;
        }
        .logout-actions {
            display: flex;
            justify-content: flex-end;
            gap: 10px;
        }
        .logout-actions button {
            min-height: 40px;
            padding: 0 18px;
            border: 1px solid #d9e1ea;
            border-radius: 8px;
            background: #fff;
            color: #122044;
            font: inherit;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
        }
        .logout-actions .logout-confirm {
            border-color: #079c9b;
            background: #079c9b;
            color: #fff;
        }
        .logout-actions button:disabled {
            cursor: wait;
            opacity: 0.65;
        }
    `;
    document.head.appendChild(style);

    function showLogoutDialog(onConfirm) {
        let busy = false;
        const backdrop = document.createElement('div');
        backdrop.className = 'logout-backdrop';
        backdrop.innerHTML = `
            <section class="logout-dialog" role="alertdialog" aria-modal="true" aria-labelledby="logoutTitle" aria-describedby="logoutDescription">
                <h2 id="logoutTitle">Log out?</h2>
                <p id="logoutDescription">Are you sure you want to log out?</p>
                <p class="logout-error" role="alert" hidden></p>
                <div class="logout-actions">
                    <button type="button" class="logout-cancel">Cancel</button>
                    <button type="button" class="logout-confirm">Log out</button>
                </div>
            </section>
        `;
        const cancelButton = backdrop.querySelector('.logout-cancel');
        const confirmButton = backdrop.querySelector('.logout-confirm');
        const errorMessage = backdrop.querySelector('.logout-error');

        function close() {
            document.removeEventListener('keydown', onKeyDown);
            backdrop.remove();
        }

        function onKeyDown(event) {
            if (event.key === 'Escape' && !busy) close();
        }

        cancelButton.addEventListener('click', function () {
            if (busy) return;
            close();
        });
        confirmButton.addEventListener('click', async function () {
            if (busy) return;
            busy = true;
            confirmButton.disabled = true;
            cancelButton.disabled = true;
            await onConfirm(dialog);
        });
        backdrop.addEventListener('click', function (event) {
            if (event.target === backdrop && !busy) close();
        });
        document.addEventListener('keydown', onKeyDown);
        document.body.appendChild(backdrop);
        cancelButton.focus();

        const dialog = {
            close,
            showError: function (message) {
                errorMessage.textContent = message;
                errorMessage.hidden = false;
                confirmButton.disabled = false;
                cancelButton.disabled = false;
                busy = false;
                confirmButton.focus();
            },
            setBusy: function (isBusy) {
                busy = isBusy;
                confirmButton.disabled = isBusy;
                cancelButton.disabled = isBusy;
            }
        };
        return dialog;
    }

    document.addEventListener('click', function (event) {
        const settingsButton = event.target.closest('.nav-item');
        if (!settingsButton || settingsButton.textContent.trim() !== 'Settings') return;

        event.preventDefault();
        showLogoutDialog(async function (dialog) {
            try {
                const response = await fetch('/api/logout', { method: 'POST' });
                const result = await response.json();
                if (!response.ok) throw new Error(result.error || 'Could not log out.');

                sessionStorage.removeItem('campusBookHubSession');
                dialog.close();
                window.location.href = '/login.html';
            } catch (error) {
                dialog.showError(error.message || 'Could not log out. Please try again.');
            }
        });
    });
})();
