use std::fs;

use color_eyre::Result;
use eyre::Ok;
use lettre::{SmtpTransport, Transport, transport::smtp::authentication::Credentials};
use serde_json::Value;

pub struct EmailService {
    mailer: SmtpTransport,
    from_address: String,
    platform_name: String,
}

impl EmailService {
    pub fn new(smtp_host: &str, smtp_user: &str, smtp_pass: &str, platform_name: &str) -> Self {
        let creds = Credentials::new(smtp_user.to_string(), smtp_pass.to_string());

        let mailer = SmtpTransport::relay(smtp_host)
            .unwrap()
            .credentials(creds)
            .build();

        Self {
            mailer,
            from_address: smtp_user.to_string(),
            platform_name: platform_name.to_string(),
        }
    }

    pub fn load_template(&self, path: &str) -> Result<String> {
        let template = fs::read_to_string(path)?;
        Ok(template)
    }

    pub async fn send_email(
        &self,
        to: &str,
        subject: &str,
        template_path: &str,
        data: &Value,
    ) -> Result<()> {
        let mut body = self.load_template(template_path)?;

        for (key, value) in data.as_object().unwrap() {
            let placeholder = format!("{{{{{}}}}}", key);
            body = body.replace(&placeholder, &value.as_str().unwrap_or_default())
        }

        let email = lettre::Message::builder()
            .from(self.from_address.parse()?)
            .to(to.parse()?)
            .subject(subject)
            .header(lettre::message::header::ContentType::TEXT_HTML)
            .body(body)?;

        self.mailer.send(&email);

        Ok(())
    }
}
