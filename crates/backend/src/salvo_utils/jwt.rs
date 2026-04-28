use coauth_jose::jwt::Jwt;
use salvo::prelude::*;

pub struct JwtResponse<T>(pub Jwt<'static, T>);

impl<T: Send> Scribe for JwtResponse<T> {
    fn render(self, res: &mut Response) {
        res.headers_mut().insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/jwt"),
        );
        res.render(Text::Plain(self.0.into_string()));
    }
}
