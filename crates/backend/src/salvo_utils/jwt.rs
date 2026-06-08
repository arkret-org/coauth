use coauth_jose::jwt::Jwt;
use salvo::prelude::*;

pub struct JwtBody<T>(pub Jwt<'static, T>);

impl<T: Send> Scribe for JwtBody<T> {
    fn render(self, res: &mut Response) {
        res.headers_mut().insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/jwt"),
        );
        res.render(Text::Plain(self.0.into_string()));
    }
}
