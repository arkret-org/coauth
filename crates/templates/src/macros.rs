/// Declares strongly-typed template rendering methods on [`Templates`] and
/// generates a `check` module that renders each template with sample data.
///
/// Each entry maps a method name to its context type and template file path.
/// The macro also collects all template paths into a static array so that
/// missing templates can be detected at startup.
///
/// Syntax is intentionally function-like to minimise syntax highlighter
/// confusion.
#[macro_export]
macro_rules! register_templates {
    {
        $(
            extra = { $( $extra_template:expr ),* $(,)? };
        )?

        $(
            $( #[ $attr:meta ] )*
            pub fn $name:ident
                $(< $( #[sample( $generic_default:tt )] $lt:tt $( : $clt:tt $(+ $dlt:tt )* )? ),+ >)?
                ( $param:ty )
            {
                $template:expr
            }
        )*
    } => {
        /// All template paths registered via the `register_templates!` macro.
        static TEMPLATES: &[&str] = &[
            $( $template, )*
            $( $( $extra_template, )* )?
        ];

        // -- Rendering methods on Templates ---------------------------------

        impl Templates {
            $(
                $(#[$attr])?
                ///
                /// # Errors
                ///
                /// Returns an error if the template fails to render.
                pub fn $name
                    $(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)?
                    (&self, context: &$param)
                -> Result<String, TemplateError> {
                    self.render_registered($template, context)
                }
            )*
        }

        // -- Sample-rendering validation ------------------------------------

        /// Module that renders every registered template with sample contexts
        /// for validation purposes.
        pub mod check {
            use super::*;

            /// Render all templates with all sample data variants.
            ///
            /// Returns a map from `(template_path, sample_identifier)` to the
            /// rendered output.
            ///
            /// # Errors
            ///
            /// Returns an error if any template fails to render with any sample.
            pub(crate) fn all<R: Rng + Clone>(
                templates: &Templates,
                now: chrono::DateTime<chrono::Utc>,
                rng: &R,
            ) -> anyhow::Result<
                ::std::collections::BTreeMap<(&'static str, SampleIdentifier), String>,
            > {
                let mut rendered_templates = ::std::collections::BTreeMap::new();
                $(
                    {
                        let mut sample_rng = rng.clone();
                        let rendered = $name $(::< _ $( , $generic_default ),* >)? (
                            templates, now, &mut sample_rng,
                        )?;
                        rendered_templates.extend(
                            rendered
                                .into_iter()
                                .map(|(sample_id, html)| (($template, sample_id), html))
                        );
                    }
                )*

                Ok(rendered_templates)
            }

            $(
                #[doc = concat!("Render the `", $template, "` template with sample contexts")]
                ///
                /// Returns the sample renders.
                ///
                /// # Errors
                ///
                /// Returns an error if the template fails to render with any of the sample.
                pub(crate) fn $name
                    < __R: Rng + Clone $( , $( $lt $( : $clt $(+ $dlt )* + TemplateContext )? ),+ )? >
                    (
                        templates: &Templates,
                        now: chrono::DateTime<chrono::Utc>,
                        rng: &mut __R,
                    )
                -> anyhow::Result<BTreeMap<SampleIdentifier, String>> {
                    templates.render_sample_set::<$param, __R>($template, now, rng)
                }
            )*
        }
    };
}
