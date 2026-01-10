use super::*;

impl BwClientIcedApp {
    pub(super) fn view(&self) -> Element<'_, Message> {
        match self.route {
            AppRoute::LoggedOut => self.view_logged_out(),
            AppRoute::Locked => self.view_locked(),
            AppRoute::Vault => self.view_vault(),
        }
    }

    fn view_logged_out(&self) -> Element<'_, Message> {
        let theme_toggle_text = match self.theme_mode {
            ThemeMode::Dark => "Light",
            ThemeMode::Light => "Dark",
        };

        let server_mode_pick = pick_list(
            vec![ServerMode::Custom, ServerMode::Official],
            Some(self.server.mode.clone()),
            Message::ServerModeChanged,
        )
        .width(Length::Shrink);

        let region_pick = pick_list(
            vec![OfficialRegion::Com, OfficialRegion::Eu],
            Some(self.server.official_region.clone()),
            Message::OfficialRegionChanged,
        )
        .width(Length::Shrink);

        let server_section = {
            let mut col = iced::widget::column![text("Server"), row![text("Mode"), server_mode_pick].spacing(8)]
                .spacing(8);

            if self.server.mode == ServerMode::Official {
                col = col.push(row![text("Region"), region_pick].spacing(8));
                col = col.push(
                    text("Official cloud will use Bitwarden's official service URLs.").size(14),
                );
            } else {
                col = col.push(
                    row![
                        text("Base URL"),
                        text_input("https://...", &self.server.custom_base_url)
                            .on_input(Message::CustomBaseUrlChanged)
                            .id(self.login_custom_base_url_id.clone())
                            .font(self.ui_font)
                            .width(Length::Fill)
                    ]
                    .spacing(8),
                );
            }

            container(col).padding(12).width(Length::Fill)
        };

        let can_continue = !self.login.email.trim().is_empty() && !self.login.password.is_empty();
        let is_in_progress = matches!(self.login_state, LoginState::InProgress { .. });
        let need_2fa = matches!(self.login_state, LoginState::NeedTwoFactor { .. });

        let mut account_col = iced::widget::column![
            text("Account"),
            row![
                text("Email"),
                text_input("", &self.login.email)
                    .on_input(Message::LoginEmailChanged)
                    .id(self.login_email_id.clone())
                    .font(self.ui_font)
                    .width(Length::Fill)
            ]
            .spacing(8),
            row![
                text("Master Password"),
                text_input("", &self.login.password)
                    .on_input(Message::LoginPasswordChanged)
                    .id(self.login_password_id.clone())
                    .font(self.ui_font)
                    .secure(true)
                    .width(Length::Fill)
            ]
            .spacing(8),
            row![
                checkbox(self.login.stay_logged_in)
                    .label("Stay Login")
                    .on_toggle(Message::LoginStayLoggedInToggled),
                text("(Stores session.json; less secure)").size(14),
            ]
            .spacing(12)
            .align_y(Alignment::Center),
            row![
                text("New Device OTP (optional)"),
                text_input("", &self.login.new_device_otp)
                    .on_input(Message::LoginNewDeviceOtpChanged)
                    .id(self.login_new_device_otp_id.clone())
                    .font(self.ui_font)
                    .width(Length::Fill)
            ]
            .spacing(8)
        ]
        .spacing(10);

        if !need_2fa {
            let continue_style = if can_continue && !is_in_progress {
                iced::widget::button::primary
            } else {
                iced::widget::button::secondary
            };

            account_col = account_col.push(
                button(text("Continue"))
                    .on_press(Message::LoginContinuePressed)
                    .padding(8)
                    .style(continue_style),
            );
        } else {
            let provider_options: Vec<String> = self.login.two_factor_providers.to_vec();

            let selected_provider: Option<String> = self.login.two_factor_provider.clone();

            let provider_pick =
                pick_list(provider_options, selected_provider, Message::TwoFactorProviderChanged)
                    .placeholder("Select")
                    .width(Length::Shrink);

            let mut twofa_col = iced::widget::column![text("Two-factor authentication required:")].spacing(8);

            if let LoginState::NeedTwoFactor {
                message,
                device_verification,
                ..
            } = &self.login_state
            {
                twofa_col = twofa_col.push(text(message.clone()).size(14));
                if *device_verification {
                    twofa_col = twofa_col
                        .push(text("Device verification is required for this login.").size(14));
                }
            }

            twofa_col = twofa_col.push(
                row![
                    text("Provider"),
                    provider_pick,
                    button(text("Send code"))
                        .on_press(Message::TwoFactorSendCodePressed)
                        .padding(6)
                ]
                .spacing(8)
                .align_y(Alignment::Center),
            );

            twofa_col = twofa_col.push(
                row![
                    text("Code"),
                    text_input("", &self.login.two_factor_code)
                        .on_input(Message::TwoFactorCodeChanged)
                        .id(self.login_two_factor_code_id.clone())
                        .font(self.ui_font)
                        .width(Length::Fill)
                ]
                .spacing(8)
                .align_y(Alignment::Center),
            );

            twofa_col = twofa_col.push(
                button(text("Submit 2FA"))
                    .on_press(Message::TwoFactorSubmitPressed)
                    .padding(8),
            );

            account_col = account_col.push(container(twofa_col).padding(8));
        }

        let status_line: Element<_> = match &self.login_state {
            LoginState::Idle => text(" ").into(),
            LoginState::InProgress { started_at } => {
                text(format!("Signing in… ({:.1}s)", started_at.elapsed().as_secs_f32())).into()
            }
            LoginState::NeedTwoFactor { .. } => text(" ").into(),
            LoginState::Error(msg) => text(msg.clone())
                .color(iced::Color::from_rgb(0.9, 0.2, 0.2))
                .into(),
        };

        let content = iced::widget::column![
            row![
                text("Sign in").size(28),
                Space::new().width(Length::Fill),
                button(text(theme_toggle_text)).on_press(Message::ThemeToggle)
            ]
            .align_y(Alignment::Center),
            rule::horizontal(1),
            server_section,
            container(account_col).padding(12),
            status_line,
        ]
        .padding(16)
        .spacing(12)
        .max_width(900);

        container(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x(Length::Fill)
            .center_y(Length::Fill)
            .into()
    }

    fn view_locked(&self) -> Element<'_, Message> {
        let theme_toggle_text = match self.theme_mode {
            ThemeMode::Dark => "Light",
            ThemeMode::Light => "Dark",
        };

        let email_line = self
            .persisted_login
            .as_ref()
            .map(|l| format!("Account: {}", l.email))
            .unwrap_or_else(|| "Account: (unknown)".to_string());

        let status_line: Element<_> = match &self.unlock_error {
            None => text(" ").into(),
            Some(msg) => text(msg.clone())
                .color(iced::Color::from_rgb(0.9, 0.2, 0.2))
                .into(),
        };

        let content = iced::widget::column![
            row![
                text("Locked").size(28),
                Space::new().width(Length::Fill),
                button(text(theme_toggle_text)).on_press(Message::ThemeToggle)
            ]
            .align_y(Alignment::Center),
            rule::horizontal(1),
            text(email_line).size(14),
            row![
                text("Master Password"),
                text_input("", &self.unlock_password)
                    .on_input(Message::UnlockPasswordChanged)
                    .id(self.unlock_password_id.clone())
                    .font(self.ui_font)
                    .secure(true)
                    .width(Length::Fill)
            ]
            .spacing(8),
            row![
                button(text("Unlock")).on_press(Message::UnlockPressed),
                button(text("Logout")).on_press(Message::LockedLogoutPressed),
            ]
            .spacing(10),
            status_line,
        ]
        .padding(16)
        .spacing(12)
        .max_width(700);

        container(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x(Length::Fill)
            .center_y(Length::Fill)
            .into()
    }

    fn view_vault(&self) -> Element<'_, Message> {
        let theme_toggle_text = match self.theme_mode {
            ThemeMode::Dark => "Light",
            ThemeMode::Light => "Dark",
        };

        let sync_status: Element<_> = match &self.sync_state {
            SyncState::Idle => text("Sync: idle").size(14).into(),
            SyncState::InProgress { started_at } => text(format!(
                "Syncing… ({:.1}s)",
                started_at.elapsed().as_secs_f32()
            ))
            .size(14)
            .into(),
            SyncState::Done { cipher_count } => {
                text(format!("Synced {cipher_count} items")).size(14).into()
            }
            SyncState::Error(msg) => text(format!("Sync error: {msg}")).size(14).into(),
        };

        let top_bar = row![
            text("Vault").size(26),
            Space::new().width(Length::Fixed(12.0)),
            text("Search"),
            text_input("", &self.vault_ui.search)
                .on_input(Message::VaultSearchChanged)
                .width(Length::FillPortion(2)),
            Space::new().width(Length::Fixed(12.0)),
            sync_status,
            button(text("Sync")).on_press(Message::VaultSyncPressed),
            Space::new().width(Length::Fill),
            button(text(theme_toggle_text)).on_press(Message::ThemeToggle),
            button(text("Lock")).on_press(Message::VaultLockPressed),
            button(text("Logout")).on_press(Message::VaultLogoutPressed),
            button(text("Password Generator")).on_press(Message::PwGenToggle),
            button(text("New")).on_press(Message::VaultNewItemPressed),
            button(text("About").font(self.ui_font)).on_press(Message::AboutToggle),
        ]
        .spacing(8)
        .align_y(Alignment::Center);

        let sidebar = self.view_sidebar();
        let items_list = self.view_items_list();
        let details = self.view_details();

        let body = row![
            container(sidebar).width(Length::Fixed(240.0)).padding(8),
            rule::vertical(1),
            container(items_list).width(Length::FillPortion(2)).padding(8),
            rule::vertical(1),
            container(details).width(Length::FillPortion(3)).padding(8),
        ]
        .height(Length::Fill);

        let mut content = iced::widget::column![top_bar, rule::horizontal(1), body]
            .spacing(8)
            .padding(8);

        if self.pwgen_open {
            content = content.push(rule::horizontal(1));
            content = content.push(self.view_pwgen_panel());
        }

        if self.about_open {
            content = content.push(rule::horizontal(1));
            content = content.push(self.view_about_panel());
        }

        container(content).width(Length::Fill).height(Length::Fill).into()
    }

    fn view_sidebar(&self) -> Element<'_, Message> {
        let mut col = iced::widget::column![
            text("All items").font(self.ui_font).size(16),
            rule::horizontal(1)
        ]
        .spacing(2);

        let mut b = button(text("All items").font(self.ui_font).size(14))
            .padding(1)
            .style(iced::widget::button::text);
        if self.vault_ui.user_selected_folder
            && self.vault_ui.selected_folder == VaultFolderFilter::AllItems
        {
            b = b.style(iced::widget::button::primary);
        }
        col = col.push(b.on_press(Message::VaultSelectFolder(VaultFolderFilter::AllItems)));

        let mut b = button(text("Favorites").font(self.ui_font).size(14))
            .padding(1)
            .style(iced::widget::button::text);
        if self.vault_ui.user_selected_folder
            && self.vault_ui.selected_folder == VaultFolderFilter::Favorites
        {
            b = b.style(iced::widget::button::primary);
        }
        col = col.push(b.on_press(Message::VaultSelectFolder(VaultFolderFilter::Favorites)));

        let mut b = button(text("Login").font(self.ui_font).size(14))
            .padding(1)
            .style(iced::widget::button::text);
        if self.vault_ui.user_selected_folder
            && self.vault_ui.selected_folder == VaultFolderFilter::Type(VaultItemType::Login)
        {
            b = b.style(iced::widget::button::primary);
        }
        col = col.push(
            b.on_press(Message::VaultSelectFolder(VaultFolderFilter::Type(VaultItemType::Login))),
        );

        let mut b = button(text("Card").font(self.ui_font).size(14))
            .padding(1)
            .style(iced::widget::button::text);
        if self.vault_ui.user_selected_folder
            && self.vault_ui.selected_folder == VaultFolderFilter::Type(VaultItemType::Card)
        {
            b = b.style(iced::widget::button::primary);
        }
        col = col.push(
            b.on_press(Message::VaultSelectFolder(VaultFolderFilter::Type(VaultItemType::Card))),
        );

        let mut b = button(text("Identity").font(self.ui_font).size(14))
            .padding(1)
            .style(iced::widget::button::text);
        if self.vault_ui.user_selected_folder
            && self.vault_ui.selected_folder == VaultFolderFilter::Type(VaultItemType::Identity)
        {
            b = b.style(iced::widget::button::primary);
        }
        col = col.push(b.on_press(Message::VaultSelectFolder(VaultFolderFilter::Type(
            VaultItemType::Identity,
        ))));

        let mut b = button(text("Note").font(self.ui_font).size(14))
            .padding(1)
            .style(iced::widget::button::text);
        if self.vault_ui.user_selected_folder
            && self.vault_ui.selected_folder == VaultFolderFilter::Type(VaultItemType::SecureNote)
        {
            b = b.style(iced::widget::button::primary);
        }
        col = col.push(b.on_press(Message::VaultSelectFolder(VaultFolderFilter::Type(
            VaultItemType::SecureNote,
        ))));

        let mut b = button(text("SSH key").font(self.ui_font).size(14))
            .padding(1)
            .style(iced::widget::button::text);
        if self.vault_ui.user_selected_folder
            && self.vault_ui.selected_folder == VaultFolderFilter::Type(VaultItemType::SshKey)
        {
            b = b.style(iced::widget::button::primary);
        }
        col = col.push(
            b.on_press(Message::VaultSelectFolder(VaultFolderFilter::Type(VaultItemType::SshKey))),
        );

        col = col.push(Space::new().height(Length::Fixed(4.0)));
        col = col.push(rule::horizontal(1));
        col = col.push(text("Folders").font(self.ui_font).size(16));
        col = col.push(rule::horizontal(1));

        for folder in &self.vault_folders {
            let selected =
                self.vault_ui.selected_folder == VaultFolderFilter::Folder(folder.id.clone());

            let mut b = button(text(folder.name.clone()).font(self.ui_font).size(14))
                .padding(3)
                .style(iced::widget::button::text);
            if self.vault_ui.user_selected_folder && selected {
                b = b.style(iced::widget::button::primary);
            }
            col = col.push(b.on_press(Message::VaultSelectFolder(VaultFolderFilter::Folder(
                folder.id.clone(),
            ))));
        }

        scrollable(col).height(Length::Fill).into()
    }

    fn view_items_list(&self) -> Element<'_, Message> {
        let mut col = iced::widget::column![
            text("Items").font(self.ui_font).size(16),
            rule::horizontal(1)
        ]
        .spacing(4);

        for item in self.visible_items() {
            let mut label = item.name.clone();
            if let Some(u) = &item.username {
                label.push_str(" — ");
                label.push_str(u);
            } else if item.item_type != VaultItemType::Login {
                label.push_str(" — ");
                label.push_str(item.item_type.label());
            }

            let selected = self
                .vault_ui
                .selected_item_id
                .as_deref()
                .is_some_and(|id| id == item.id);

            let mut b = button(text(label).font(self.ui_font).size(14))
                .padding(2)
                .width(Length::Fill)
                .style(iced::widget::button::text);
            if self.vault_ui.user_selected_item && selected {
                b = b.style(iced::widget::button::primary);
            }
            col = col.push(b.on_press(Message::VaultSelectItem(item.id.clone())));
        }

        scrollable(col).height(Length::Fill).into()
    }

    fn view_details(&self) -> Element<'_, Message> {
        let mut col = iced::widget::column![text("Details").size(20), rule::horizontal(1)].spacing(8);

        match &self.item_op_state {
            ItemOpState::Idle => {}
            ItemOpState::InProgress { started_at } => {
                col = col.push(
                    text(format!("Working… ({:.1}s)", started_at.elapsed().as_secs_f32())).size(14),
                );
            }
            ItemOpState::Error(msg) => {
                col = col.push(text(msg.clone()));
            }
        }

        let is_busy = matches!(self.item_op_state, ItemOpState::InProgress { .. });

        match &self.details_mode {
            DetailsMode::View => {
                if let Some(item) = self.selected_item() {
                    col = col.push(text(&item.name).size(18));
                    col = col.push(text(item.item_type.label()).size(14));

                    col = col.push(Space::new().height(Length::Fixed(6.0)));

                    col = col.push(
                        row![button(text("Edit")).on_press(Message::VaultEditItemPressed),]
                            .spacing(8),
                    );

                    col = col.push(rule::horizontal(1));

                    col = col.push(self.view_item_details(item));
                } else {
                    col = col.push(text("(No item selected)"));
                }
            }
            DetailsMode::Edit {
                draft,
                is_new,
                confirm_delete,
            } => {
                col = col.push(text(if *is_new { "New item" } else { "Edit item" }).size(18));

                if *is_new {
                    let pick = pick_list(
                        Self::pickable_item_types(),
                        Some(draft.item_type),
                        Message::EditItemTypeChanged,
                    );
                    col = col.push(row![text("Type"), pick].spacing(8));
                } else {
                    col = col.push(row![text("Type"), text(draft.item_type.label())].spacing(8));
                }

                let selected_choice = draft
                    .folder_id
                    .as_deref()
                    .and_then(|fid| {
                        self.vault_folders
                            .iter()
                            .find(|f| f.id == fid)
                            .map(|f| FolderChoice {
                                label: f.name.clone(),
                                id: Some(f.id.clone()),
                            })
                    })
                    .or_else(|| Some(FolderChoice {
                        label: "(none)".to_string(),
                        id: None,
                    }));

                let mut folder_options: Vec<FolderChoice> = Vec::new();
                folder_options.push(FolderChoice {
                    label: "(none)".to_string(),
                    id: None,
                });
                for f in &self.vault_folders {
                    folder_options.push(FolderChoice {
                        label: f.name.clone(),
                        id: Some(f.id.clone()),
                    });
                }

                let folder_pick = pick_list(folder_options, selected_choice, |choice: FolderChoice| {
                    Message::EditFolderChanged(choice.id)
                });

                col = col.push(
                    row![
                        text("Name"),
                        text_input("", &draft.name)
                            .id(self.edit_name_id.clone())
                            .on_input(Message::EditNameChanged)
                            .width(Length::Fill)
                    ]
                    .spacing(8),
                );
                col = col.push(row![text("Folder"), folder_pick].spacing(8));
                col = col.push(
                    checkbox(draft.favorite)
                        .label("Favorite")
                        .on_toggle(Message::EditFavoriteToggled),
                );

                col = col.push(rule::horizontal(1));

                col = col.push(self.view_edit_fields(draft.as_ref()));

                col = col.push(rule::horizontal(1));

                col = col.push(
                    row![
                        button(text("Cancel")).on_press(Message::VaultCancelEditPressed),
                        button(text("Save"))
                            .on_press(Message::VaultSaveItemPressed)
                            .style(iced::widget::button::primary),
                    ]
                    .spacing(8),
                );

                if !*is_new {
                    col = col.push(Space::new().height(Length::Fixed(8.0)));
                    col = col.push(
                        checkbox(*confirm_delete)
                            .label("Confirm delete")
                            .on_toggle(Message::VaultConfirmDeleteToggled),
                    );
                    let mut del = button(text("Delete")).padding(6);
                    if *confirm_delete {
                        del = del.style(iced::widget::button::danger);
                    }
                    if !is_busy {
                        col = col.push(del.on_press(Message::VaultDeleteItemPressed));
                    }
                }
            }
        }

        scrollable(col).height(Length::Fill).into()
    }

    fn view_item_details(&self, item: &VaultItem) -> Element<'_, Message> {
        let mut col = iced::widget::column![].spacing(8).align_x(Alignment::Start);

        match item.item_type {
            VaultItemType::Login => {
                if let Some(u) = &item.username {
                    col = col.push(
                        row![
                            text("Username:"),
                            text(u.clone()),
                            Space::new().width(Length::Fill),
                            button(text("Copy"))
                                .on_press(Message::CopyToClipboard(u.clone()))
                                .padding(4)
                        ]
                        .spacing(8)
                        .align_y(Alignment::Center),
                    );
                }

                if let Some(p) = &item.password {
                    let display = if self.vault_ui.show_password {
                        p.clone()
                    } else {
                        "********".to_string()
                    };

                    let copy_btn = button(text("Copy"))
                        .on_press(Message::CopyToClipboard(p.clone()))
                        .padding(4);

                    col = col.push(
                        row![
                            text("Password:"),
                            text(display),
                            Space::new().width(Length::Fill),
                            button(text(if self.vault_ui.show_password {
                                "Hide"
                            } else {
                                "Show"
                            }))
                            .on_press(Message::ToggleShowPassword)
                            .padding(4),
                            copy_btn,
                        ]
                        .spacing(8)
                        .align_y(Alignment::Center),
                    );

                    col = col.push(
                        checkbox(self.vault_ui.clear_password_clipboard_after_30s)
                            .label("Auto-clear copied password after 30s")
                            .on_toggle(Message::ToggleAutoClearPassword),
                    );
                }

                if let Some(t) = &item.totp {
                    match totp::parse_totp(t) {
                        Ok(cfg) => {
                            let code = cfg.generate(self.unix_now);
                            let remain = totp::seconds_until_rollover(self.unix_now, cfg.period());

                            col = col.push(
                                row![
                                    text("TOTP:"),
                                    text(code.clone()),
                                    button(text("Copy")).on_press(Message::CopyToClipboard(code))
                                ]
                                .spacing(8)
                                .align_y(Alignment::Center),
                            );
                            col = col.push(text(format!("Expires in {remain}s")).size(14));
                        }
                        Err(e) => {
                            col = col.push(text(format!("Invalid TOTP: {e}")));
                        }
                    }
                }

                if !item.uris.is_empty() {
                    col = col.push(text("URLs:").size(16));
                    col = col.push(
                        button(text("Copy all"))
                            .on_press(Message::CopyToClipboard(item.uris.join("\n")))
                            .padding(4),
                    );
                    for u in &item.uris {
                        // show URL text on its own line and place copy button on a row below aligned to the right
                        col = col.push(
                            iced::widget::column![
                                text(u.clone()).width(Length::Fill),
                                row![
                                    Space::new().width(Length::Fill),
                                    button(text("Copy"))
                                        .on_press(Message::CopyToClipboard(u.clone()))
                                        .padding(4)
                                ]
                                .spacing(0)
                                .align_y(Alignment::Center),
                            ]
                            .spacing(4),
                        );
                    }
                }
            }
            VaultItemType::SecureNote => {
                if let Some(n) = &item.notes {
                    col = col.push(text("Notes:").size(16));
                    col = col.push(text(n.clone()));
                } else {
                    col = col.push(text("(No notes)"));
                }
            }
            VaultItemType::Card => {
                let Some(card) = &item.card else {
                    return text("(No card data)").into();
                };

                let show =
                    |label: &str, value: Option<&String>, copy: bool| -> Option<Element<Message>> {
                        let v = value?.clone();
                        let label = label.to_string();

                        let mut r = row![text(label), text(v.clone())]
                            .spacing(8)
                            .align_y(Alignment::Center);
                        if copy {
                            r = r.push(button(text("Copy")).on_press(Message::CopyToClipboard(v)));
                        }
                        Some(r.into())
                    };

                if let Some(e) = show("Cardholder:", card.cardholder_name.as_ref(), true) {
                    col = col.push(e);
                }
                if let Some(e) = show("Brand:", card.brand.as_ref(), false) {
                    col = col.push(e);
                }
                if let Some(e) = show("Number:", card.number.as_ref(), true) {
                    col = col.push(e);
                }
                let exp = match (&card.exp_month, &card.exp_year) {
                    (Some(m), Some(y)) => Some(format!("{m}/{y}")),
                    (Some(m), None) => Some(m.clone()),
                    (None, Some(y)) => Some(y.clone()),
                    (None, None) => None,
                };
                if let Some(v) = exp {
                    col = col.push(row![text("Expires:"), text(v)].spacing(8));
                }
                if let Some(e) = show("Code:", card.code.as_ref(), true) {
                    col = col.push(e);
                }
            }
            VaultItemType::Identity => {
                let Some(ident) = &item.identity else {
                    return text("(No identity data)").into();
                };

                let maybe = |v: Option<&String>| v.cloned().unwrap_or_default();

                // Build left and right columns so the content is symmetrically split across the center
                let mut left_col = iced::widget::column![].spacing(6).align_x(Alignment::Start);
                let mut right_col = iced::widget::column![].spacing(6).align_x(Alignment::Start);

                // Left column entries
                if ident.title.is_some() {
                    left_col = left_col.push(
                        row![
                            text("Title:"),
                            Space::new().width(Length::Fixed(6.0)),
                            text(maybe(ident.title.as_ref()))
                        ]
                        .spacing(6),
                    );
                }
                if ident.middle_name.is_some() {
                    left_col = left_col.push(
                        row![
                            text("Middle:"),
                            Space::new().width(Length::Fixed(6.0)),
                            text(maybe(ident.middle_name.as_ref()))
                        ]
                        .spacing(6),
                    );
                }
                if ident.company.is_some() {
                    left_col = left_col.push(
                        row![
                            text("Company:"),
                            Space::new().width(Length::Fixed(6.0)),
                            text(maybe(ident.company.as_ref()))
                        ]
                        .spacing(6),
                    );
                }
                if let Some(e) = &ident.email {
                    left_col = left_col.push(
                        row![
                            text("Email:"),
                            text(e.clone()),
                            Space::new().width(Length::Fill),
                            button(text("Copy"))
                                .on_press(Message::CopyToClipboard(e.clone()))
                                .padding(4)
                        ]
                        .spacing(6),
                    );
                }
                if let Some(p) = &ident.phone {
                    left_col = left_col.push(
                        row![
                            text("Phone:"),
                            text(p.clone()),
                            Space::new().width(Length::Fill),
                            button(text("Copy"))
                                .on_press(Message::CopyToClipboard(p.clone()))
                                .padding(4)
                        ]
                        .spacing(6),
                    );
                }
                if let Some(a1) = &ident.address1 {
                    left_col = left_col.push(row![text("Address1:"), text(a1.clone())].spacing(6));
                }
                if ident.address2.is_some() {
                    left_col = left_col
                        .push(row![text("Address2:"), text(maybe(ident.address2.as_ref()))].spacing(6));
                }
                if let Some(s) = &ident.ssn {
                    left_col = left_col.push(
                        row![
                            text("SSN:"),
                            text(s.clone()),
                            Space::new().width(Length::Fill),
                            button(text("Copy"))
                                .on_press(Message::CopyToClipboard(s.clone()))
                                .padding(4)
                        ]
                        .spacing(6),
                    );
                }

                // Right column entries
                if ident.first_name.is_some() {
                    right_col = right_col
                        .push(row![text("First:"), text(maybe(ident.first_name.as_ref()))].spacing(6));
                }
                if ident.last_name.is_some() {
                    right_col = right_col
                        .push(row![text("Last:"), text(maybe(ident.last_name.as_ref()))].spacing(6));
                }
                if ident.username.is_some() {
                    right_col = right_col.push(
                        row![
                            text("User:"),
                            text(maybe(ident.username.as_ref())),
                            Space::new().width(Length::Fill),
                            button(text("Copy"))
                                .on_press(Message::CopyToClipboard(maybe(ident.username.as_ref())))
                                .padding(4)
                        ]
                        .spacing(6),
                    );
                }
                if ident.address3.is_some() {
                    right_col = right_col.push(
                        row![
                            text("Address3:"),
                            text(maybe(ident.address3.as_ref())),
                            Space::new().width(Length::Fill),
                            button(text("Copy"))
                                .on_press(Message::CopyToClipboard(maybe(ident.address3.as_ref())))
                                .padding(4)
                        ]
                        .spacing(6),
                    );
                }
                if ident.city.is_some() {
                    right_col = right_col
                        .push(row![text("City:"), text(maybe(ident.city.as_ref()))].spacing(6));
                }
                if ident.state.is_some() {
                    right_col = right_col
                        .push(row![text("State:"), text(maybe(ident.state.as_ref()))].spacing(6));
                }
                if ident.country.is_some() {
                    right_col = right_col
                        .push(row![text("Country:"), text(maybe(ident.country.as_ref()))].spacing(6));
                }
                if ident.postal_code.is_some() {
                    right_col = right_col
                        .push(row![text("Postal:"), text(maybe(ident.postal_code.as_ref()))].spacing(6));
                }
                if ident.passport_number.is_some() {
                    right_col = right_col
                        .push(row![text("Passport:"), text(maybe(ident.passport_number.as_ref()))].spacing(6));
                }
                if ident.license_number.is_some() {
                    right_col = right_col
                        .push(row![text("License:"), text(maybe(ident.license_number.as_ref()))].spacing(6));
                }

                let left_container = container(left_col).width(Length::FillPortion(1));
                let right_container = container(right_col).width(Length::FillPortion(1));

                col = col.push(
                    row![
                        left_container,
                        Space::new().width(Length::Fixed(16.0)),
                        right_container
                    ]
                    .spacing(8),
                );
            }
            VaultItemType::SshKey => {
                let Some(ssh) = &item.ssh_key else {
                    return text("(No SSH key data)").into();
                };

                let show =
                    |label: &str, value: Option<&String>, copy: bool| -> Option<Element<Message>> {
                        let v = value?.clone();
                        let label = label.to_string();

                        let mut r = row![text(label), text(v.clone())]
                            .spacing(8)
                            .align_y(Alignment::Center);
                        if copy {
                            r = r.push(button(text("Copy")).on_press(Message::CopyToClipboard(v)));
                        }
                        Some(r.into())
                    };

                if let Some(e) = show("Fingerprint:", ssh.fingerprint.as_ref(), true) {
                    col = col.push(e);
                }
                if let Some(v) = &ssh.public_key {
                    col = col.push(text("Public key:").size(16));
                    col = col.push(text(v.clone()));
                    col = col.push(button(text("Copy public")).on_press(Message::CopyToClipboard(
                        v.clone(),
                    )));
                }
                if let Some(v) = &ssh.private_key {
                    col = col.push(text("Private key:").size(16));
                    let display = if self.vault_ui.show_password {
                        v.clone()
                    } else {
                        "********".to_string()
                    };
                    col = col.push(text(display));
                    col = col.push(
                        row![
                            button(text(if self.vault_ui.show_password {
                                "Hide"
                            } else {
                                "Show"
                            }))
                            .on_press(Message::ToggleShowPassword),
                            button(text("Copy private"))
                                .on_press(Message::CopyToClipboard(v.clone())),
                        ]
                        .spacing(8),
                    );
                }
            }
            _ => {
                col = col.push(text("(Details not implemented for this type yet)"));
            }
        }

        if item.item_type != VaultItemType::SecureNote
            && let Some(n) = &item.notes
        {
            col = col.push(Space::new().height(Length::Fixed(6.0)));
            col = col.push(text("Notes:").size(16));
            col = col.push(text(n.clone()));
        }

        col.into()
    }

    fn view_edit_fields(&self, draft: &EditDraft) -> Element<'_, Message> {
        let mut col = iced::widget::column![].spacing(8);

        match draft.item_type {
            VaultItemType::Login => {
                col = col.push(
                    row![
                        text("Username"),
                        text_input("", &draft.username)
                            .id(self.edit_username_id.clone())
                            .on_input(Message::EditUsernameChanged)
                            .width(Length::Fill)
                    ]
                    .spacing(8),
                );
                col = col.push(
                    row![
                        text("Password"),
                        text_input("", &draft.password)
                            .id(self.edit_password_id.clone())
                            .on_input(Message::EditPasswordChanged)
                            .secure(!self.vault_ui.show_password)
                            .width(Length::Fill),
                        button(if self.vault_ui.show_password { "Hide" } else { "Show" })
                            .on_press(Message::ToggleShowPassword),
                        button(text("Gen"))
                            .on_press(Message::EditGeneratePassword)
                            .padding(4),
                    ]
                    .spacing(8)
                    .align_y(Alignment::Center),
                );
                col = col.push(
                    row![
                        text("TOTP"),
                        text_input("Base32 secret or otpauth://totp/...", &draft.totp)
                            .id(self.edit_totp_id.clone())
                            .on_input(Message::EditTotpChanged)
                            .width(Length::Fill)
                    ]
                    .spacing(8),
                );
                col = col.push(text("URLs (one per line)"));
                col = col.push(
                    text_input("", &draft.uris)
                        .id(self.edit_uris_id.clone())
                        .on_input(Message::EditUrisChanged)
                        .width(Length::Fill),
                );
                col = col.push(text("Notes"));
                if let Some(content) = &self.edit_notes_content {
                    let editor: Element<_> = iced::widget::TextEditor::new(content)
                        .on_action(Message::EditNotesAction)
                        .height(Length::Fixed(120.0))
                        .padding(4)
                        .font(self.ui_font)
                        .into();
                    col = col.push(editor);
                } else {
                    col = col.push(
                        text_input("", &draft.notes)
                            .on_input(Message::EditNotesChanged)
                            .width(Length::Fill),
                    );
                }
            }
            VaultItemType::SecureNote => {
                col = col.push(text("Notes"));
                if let Some(content) = &self.edit_notes_content {
                    let editor: Element<_> = iced::widget::TextEditor::new(content)
                        .on_action(Message::EditNotesAction)
                        .height(Length::Fixed(160.0))
                        .padding(4)
                        .font(self.ui_font)
                        .into();
                    col = col.push(editor);
                } else {
                    col = col.push(
                        text_input("", &draft.notes)
                            .on_input(Message::EditNotesChanged)
                            .width(Length::Fill),
                    );
                }
            }
            VaultItemType::Card => {
                col = col.push(
                    row![
                        text("Cardholder"),
                        text_input("", &draft.cardholder_name)
                            .on_input(Message::EditCardholderChanged)
                            .width(Length::Fill)
                    ]
                    .spacing(8),
                );
                col = col.push(
                    row![
                        text("Brand"),
                        text_input("", &draft.card_brand)
                            .on_input(Message::EditCardBrandChanged)
                            .width(Length::Fill)
                    ]
                    .spacing(8),
                );
                col = col.push(
                    row![
                        text("Number"),
                        text_input("", &draft.card_number)
                            .on_input(Message::EditCardNumberChanged)
                            .width(Length::Fill)
                    ]
                    .spacing(8),
                );
                col = col.push(
                    row![
                        text("Exp month"),
                        text_input("", &draft.card_exp_month)
                            .on_input(Message::EditCardExpMonthChanged)
                            .width(Length::Fill)
                    ]
                    .spacing(8),
                );
                col = col.push(
                    row![
                        text("Exp year"),
                        text_input("", &draft.card_exp_year)
                            .on_input(Message::EditCardExpYearChanged)
                            .width(Length::Fill)
                    ]
                    .spacing(8),
                );
                col = col.push(
                    row![
                        text("Code"),
                        text_input("", &draft.card_code)
                            .on_input(Message::EditCardCodeChanged)
                            .width(Length::Fill)
                    ]
                    .spacing(8),
                );
                col = col.push(text("Notes"));
                if let Some(content) = &self.edit_notes_content {
                    let editor: Element<_> = iced::widget::TextEditor::new(content)
                        .on_action(Message::EditNotesAction)
                        .height(Length::Fixed(120.0))
                        .padding(4)
                        .font(self.ui_font)
                        .into();
                    col = col.push(editor);
                } else {
                    col = col.push(
                        text_input("", &draft.notes)
                            .on_input(Message::EditNotesChanged)
                            .width(Length::Fill),
                    );
                }
            }
            VaultItemType::Identity => {
                // Title | First
                col = col.push(
                    row![
                        iced::widget::column![
                            text("Title"),
                            text_input("", &draft.ident_title)
                                .on_input(Message::EditIdentTitleChanged)
                                .width(Length::Fill)
                        ],
                        Space::new().width(Length::Fixed(8.0)),
                        iced::widget::column![
                            text("First"),
                            text_input("", &draft.ident_first)
                                .on_input(Message::EditIdentFirstChanged)
                                .width(Length::Fill)
                        ],
                    ]
                    .spacing(8),
                );
                // Middle | Last
                col = col.push(
                    row![
                        iced::widget::column![
                            text("Middle"),
                            text_input("", &draft.ident_middle)
                                .on_input(Message::EditIdentMiddleChanged)
                                .width(Length::Fill)
                        ],
                        Space::new().width(Length::Fixed(8.0)),
                        iced::widget::column![
                            text("Last"),
                            text_input("", &draft.ident_last)
                                .on_input(Message::EditIdentLastChanged)
                                .width(Length::Fill)
                        ],
                    ]
                    .spacing(8),
                );
                // Company | User
                col = col.push(
                    row![
                        iced::widget::column![
                            text("Company"),
                            text_input("", &draft.ident_company)
                                .on_input(Message::EditIdentCompanyChanged)
                                .width(Length::Fill)
                        ],
                        Space::new().width(Length::Fixed(8.0)),
                        iced::widget::column![
                            text("User"),
                            text_input("", &draft.ident_username)
                                .on_input(Message::EditIdentUsernameChanged)
                                .width(Length::Fill)
                        ],
                    ]
                    .spacing(8),
                );
                // Email
                col = col.push(
                    row![
                        text("Email"),
                        text_input("", &draft.ident_email)
                            .on_input(Message::EditIdentEmailChanged)
                            .width(Length::Fill)
                    ]
                    .spacing(8),
                );
                // Phone
                col = col.push(
                    row![
                        text("Phone"),
                        text_input("", &draft.ident_phone)
                            .on_input(Message::EditIdentPhoneChanged)
                            .width(Length::Fill)
                    ]
                    .spacing(8),
                );
                // Address1
                col = col.push(
                    row![
                        text("Address1"),
                        text_input("", &draft.ident_address1)
                            .on_input(Message::EditIdentAddress1Changed)
                            .width(Length::Fill)
                    ]
                    .spacing(8),
                );
                // Address2 | Address3
                col = col.push(
                    row![
                        iced::widget::column![
                            text("Address2"),
                            text_input("", &draft.ident_address2)
                                .on_input(Message::EditIdentAddress2Changed)
                                .width(Length::Fill)
                        ],
                        Space::new().width(Length::Fixed(8.0)),
                        iced::widget::column![
                            text("Address3"),
                            text_input("", &draft.ident_address3)
                                .on_input(Message::EditIdentAddress3Changed)
                                .width(Length::Fill)
                        ],
                    ]
                    .spacing(8),
                );
                // City | State
                col = col.push(
                    row![
                        iced::widget::column![
                            text("City"),
                            text_input("", &draft.ident_city)
                                .on_input(Message::EditIdentCityChanged)
                                .width(Length::Fill)
                        ],
                        Space::new().width(Length::Fixed(8.0)),
                        iced::widget::column![
                            text("State"),
                            text_input("", &draft.ident_state)
                                .on_input(Message::EditIdentStateChanged)
                                .width(Length::Fill)
                        ],
                    ]
                    .spacing(8),
                );
                // Country | Postal
                col = col.push(
                    row![
                        iced::widget::column![
                            text("Country"),
                            text_input("", &draft.ident_country)
                                .on_input(Message::EditIdentCountryChanged)
                                .width(Length::Fill)
                        ],
                        Space::new().width(Length::Fixed(8.0)),
                        iced::widget::column![
                            text("Postal"),
                            text_input("", &draft.ident_postal)
                                .on_input(Message::EditIdentPostalChanged)
                                .width(Length::Fill)
                        ],
                    ]
                    .spacing(8),
                );
                // SSN
                col = col.push(
                    row![
                        text("SSN"),
                        text_input("", &draft.ident_ssn)
                            .on_input(Message::EditIdentSsnChanged)
                            .width(Length::Fill)
                    ]
                    .spacing(8),
                );
                // Passport | License
                col = col.push(
                    row![
                        iced::widget::column![
                            text("Passport"),
                            text_input("", &draft.ident_passport)
                                .on_input(Message::EditIdentPassportChanged)
                                .width(Length::Fill)
                        ],
                        Space::new().width(Length::Fixed(8.0)),
                        iced::widget::column![
                            text("License"),
                            text_input("", &draft.ident_license)
                                .on_input(Message::EditIdentLicenseChanged)
                                .width(Length::Fill)
                        ],
                    ]
                    .spacing(8),
                );
                col = col.push(text("Notes"));
                if let Some(content) = &self.edit_notes_content {
                    let editor: Element<_> = iced::widget::TextEditor::new(content)
                        .on_action(Message::EditNotesAction)
                        .height(Length::Fixed(120.0))
                        .padding(4)
                        .font(self.ui_font)
                        .into();
                    col = col.push(editor);
                } else {
                    col = col.push(
                        text_input("", &draft.notes)
                            .on_input(Message::EditNotesChanged)
                            .width(Length::Fill),
                    );
                }
            }
            VaultItemType::SshKey => {
                col = col.push(
                    row![
                        text("Fingerprint"),
                        text_input("", &draft.ssh_fingerprint)
                            .on_input(Message::EditSshFingerprintChanged)
                            .width(Length::Fill)
                    ]
                    .spacing(8),
                );
                col = col.push(text("Public key"));
                col = col.push(
                    text_input("", &draft.ssh_public)
                        .on_input(Message::EditSshPublicChanged)
                        .width(Length::Fill),
                );
                col = col.push(text("Private key"));
                col = col.push(
                    text_input("", &draft.ssh_private)
                        .on_input(Message::EditSshPrivateChanged)
                        .width(Length::Fill),
                );
                col = col.push(text("Notes"));
                if let Some(content) = &self.edit_notes_content {
                    let editor: Element<_> = iced::widget::TextEditor::new(content)
                        .on_action(Message::EditNotesAction)
                        .height(Length::Fixed(120.0))
                        .padding(4)
                        .font(self.ui_font)
                        .into();
                    col = col.push(editor);
                } else {
                    col = col.push(
                        text_input("", &draft.notes)
                            .on_input(Message::EditNotesChanged)
                            .width(Length::Fill),
                    );
                }
            }
            _ => {
                col = col.push(text("(Edit UI not implemented for this type)"));
            }
        }

        col.into()
    }

    fn view_pwgen_panel(&self) -> Element<'_, Message> {
        let theme_toggle_text = if self.pwgen_open { "Close" } else { "Open" };

        let mut col = iced::widget::column![
            row![
                text("Password Generator").size(18),
                Space::new().width(Length::Fill),
                button(text(theme_toggle_text)).on_press(Message::PwGenToggle)
            ]
            .align_y(Alignment::Center),
            row![
                text_input("", &self.pwgen_password).width(Length::Fill),
                button(text("Copy")).on_press(Message::PwGenCopy),
                button(text("Regenerate")).on_press(Message::PwGenRegenerate),
            ]
            .spacing(8)
            .align_y(Alignment::Center),
        ]
        .spacing(8);

        if let Some(err) = &self.pwgen_error {
            col = col.push(text(err.clone()));
        }

        col = col.push(rule::horizontal(1));
        col = col.push(text("Options").size(16));

        let len = self.pwgen_options.length;
        col = col.push(
            row![
                text(format!("Length: {len}")),
                button(text("-")).on_press(Message::PwGenLengthChanged(
                    len.saturating_sub(1).max(1),
                )),
                button(text("+")).on_press(Message::PwGenLengthChanged((len + 1).min(128))),
            ]
            .spacing(8)
            .align_y(Alignment::Center),
        );

        col = col.push(
            checkbox(self.pwgen_options.include_upper)
                .label("A-Z")
                .on_toggle(Message::PwGenIncludeUpper),
        );
        col = col.push(
            checkbox(self.pwgen_options.include_lower)
                .label("a-z")
                .on_toggle(Message::PwGenIncludeLower),
        );
        col = col.push(
            checkbox(self.pwgen_options.include_digits)
                .label("0-9")
                .on_toggle(Message::PwGenIncludeDigits),
        );
        col = col.push(
            checkbox(self.pwgen_options.include_special)
                .label("!@#$%^&*")
                .on_toggle(Message::PwGenIncludeSpecial),
        );

        let min_numbers = self.pwgen_options.min_numbers;
        col = col.push(
            row![
                text(format!("Minimum numbers: {min_numbers}")),
                button(text("-")).on_press(Message::PwGenMinNumbersChanged(
                    min_numbers.saturating_sub(1),
                )),
                button(text("+")).on_press(Message::PwGenMinNumbersChanged(min_numbers + 1)),
            ]
            .spacing(8)
            .align_y(Alignment::Center),
        );

        let min_special = self.pwgen_options.min_special;
        col = col.push(
            row![
                text(format!("Minimum special: {min_special}")),
                button(text("-")).on_press(Message::PwGenMinSpecialChanged(
                    min_special.saturating_sub(1),
                )),
                button(text("+")).on_press(Message::PwGenMinSpecialChanged(min_special + 1)),
            ]
            .spacing(8)
            .align_y(Alignment::Center),
        );

        container(col).padding(8).into()
    }

    fn view_about_panel(&self) -> Element<'_, Message> {
        let col = iced::widget::column![
            row![
                text("About BwClient").size(18),
                Space::new().width(Length::Fill),
                button(text("Close")).on_press(Message::AboutToggle)
            ]
            .align_y(Alignment::Center),
            text("Version: 2026.1.0"),
            text("Author: HUANG KUNLUN"),
            row![
                text("GitHub:"),
                text("https://github.com/hkwk/bwclient"),
                button(text("Copy")).on_press(Message::CopyToClipboard(
                    "https://github.com/hkwk/bwclient".to_string()
                ))
            ]
            .spacing(8)
            .align_y(Alignment::Center),
            row![
                text("License:"),
                text("Apache-2.0 (https://www.apache.org/licenses/LICENSE-2.0)"),
                button(text("Copy")).on_press(Message::CopyToClipboard(
                    "https://www.apache.org/licenses/LICENSE-2.0".to_string()
                ))
            ]
            .spacing(8)
            .align_y(Alignment::Center),
            text("Copyright (c) 2026 HUANG KUNLUN. Licensed under the Apache License 2.0."),
        ]
        .spacing(8);

        container(col).padding(8).into()
    }
}
