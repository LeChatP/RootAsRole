use std::{
    fmt,
    process::{ExitCode, Termination},
};

use libc::{EACCES, EFAULT, EINVAL, ENOENT, EPERM};

/// Critical security program errors with minimal information exposure
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SrError {
    /// Invalid arguments provided
    InvalidAgruments,
    /// Authentication failed
    AuthenticationFailed,
    /// Configuration error
    ConfigurationError,
    /// Insufficient privileges to execute the program
    InsufficientPrivileges,
    /// Permission denied
    PermissionDenied,
    /// Command execution failed
    ExecutionFailed,
    /// Internal system error
    SystemError,
}

impl Termination for SrError {
    fn report(self) -> ExitCode {
        ExitCode::from(match self {
            Self::InvalidAgruments => EINVAL,
            Self::AuthenticationFailed => EACCES,
            Self::ConfigurationError => EINVAL,
            Self::InsufficientPrivileges => EACCES,
            Self::ExecutionFailed => ENOENT,
            Self::SystemError => EFAULT,
            Self::PermissionDenied => EPERM,
        } as u8)
    }
}

impl fmt::Display for SrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Minimal, non-revealing error messages
        let msg = match self {
            Self::AuthenticationFailed => "Authentication failed",
            Self::ConfigurationError => "Configuration error",
            Self::InsufficientPrivileges => "Insufficient privileges",
            Self::PermissionDenied => "Permission denied",
            Self::ExecutionFailed => "Execution failed",
            Self::SystemError => "System error",
            Self::InvalidAgruments => "Invalid arguments",
        };
        write!(f, "{}", msg)
    }
}

impl std::error::Error for SrError {}

/// Result type for sr operations
pub type SrResult<T> = Result<T, SrError>;

/// Auto-conversions for common error types
impl From<std::io::Error> for SrError {
    fn from(err: std::io::Error) -> Self {
        match err.kind() {
            std::io::ErrorKind::PermissionDenied => SrError::PermissionDenied,
            std::io::ErrorKind::NotFound => SrError::ExecutionFailed,
            _ => SrError::SystemError,
        }
    }
}

impl From<capctl::Error> for SrError {
    fn from(_: capctl::Error) -> Self {
        SrError::InsufficientPrivileges
    }
}

impl From<serde_json::Error> for SrError {
    fn from(_: serde_json::Error) -> Self {
        SrError::ConfigurationError
    }
}

impl<E> From<cbor4ii::serde::DecodeError<E>> for SrError {
    fn from(_: cbor4ii::serde::DecodeError<E>) -> Self {
        SrError::ConfigurationError
    }
}

impl<E> From<cbor4ii::serde::EncodeError<E>> for SrError {
    fn from(_: cbor4ii::serde::EncodeError<E>) -> Self {
        SrError::ConfigurationError
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    use std::process::ExitCode;

    #[test]
    fn test_error_display() {
        assert_eq!(
            SrError::AuthenticationFailed.to_string(),
            "Authentication failed"
        );
        assert_eq!(
            SrError::ConfigurationError.to_string(),
            "Configuration error"
        );
        assert_eq!(
            SrError::InsufficientPrivileges.to_string(),
            "Insufficient privileges"
        );
        assert_eq!(SrError::PermissionDenied.to_string(), "Permission denied");
        assert_eq!(SrError::ExecutionFailed.to_string(), "Execution failed");
        assert_eq!(SrError::SystemError.to_string(), "System error");
        assert_eq!(SrError::InvalidAgruments.to_string(), "Invalid arguments");
    }

    #[test]
    fn test_error_debug() {
        // Ensure Debug trait is properly derived
        let error = SrError::AuthenticationFailed;
        assert_eq!(format!("{:?}", error), "AuthenticationFailed");
    }

    #[test]
    fn test_error_clone_and_eq() {
        let error1 = SrError::PermissionDenied;
        let error2 = error1.clone();
        assert_eq!(error1, error2);

        let error3 = SrError::SystemError;
        assert_ne!(error1, error3);
    }

    #[test]
    fn test_termination_exit_codes() {
        assert_eq!(
            SrError::InvalidAgruments.report(),
            ExitCode::from(EINVAL as u8)
        );
        assert_eq!(
            SrError::AuthenticationFailed.report(),
            ExitCode::from(EACCES as u8)
        );
        assert_eq!(
            SrError::ConfigurationError.report(),
            ExitCode::from(EINVAL as u8)
        );
        assert_eq!(
            SrError::InsufficientPrivileges.report(),
            ExitCode::from(EACCES as u8)
        );
        assert_eq!(
            SrError::ExecutionFailed.report(),
            ExitCode::from(ENOENT as u8)
        );
        assert_eq!(SrError::SystemError.report(), ExitCode::from(EFAULT as u8));
        assert_eq!(
            SrError::PermissionDenied.report(),
            ExitCode::from(EPERM as u8)
        );
    }

    #[test]
    fn test_error_trait() {
        let error: &dyn Error = &SrError::SystemError;
        assert_eq!(error.to_string(), "System error");
        assert!(error.source().is_none());
    }

    #[test]
    fn test_from_io_error() {
        let permission_denied = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "test");
        let sr_error: SrError = permission_denied.into();
        assert_eq!(sr_error, SrError::PermissionDenied);

        let not_found = std::io::Error::new(std::io::ErrorKind::NotFound, "test");
        let sr_error: SrError = not_found.into();
        assert_eq!(sr_error, SrError::ExecutionFailed);

        let other = std::io::Error::other("test");
        let sr_error: SrError = other.into();
        assert_eq!(sr_error, SrError::SystemError);
    }

    #[test]
    fn test_from_capctl_error() {
        // Test that the From implementation exists and compiles
        // We use capctl::Error::last() to create an error instance
        let capctl_error = capctl::Error::last();
        let sr_error: SrError = capctl_error.into();

        // This test ensures the From trait implementation compiles correctly
        // and returns the expected error type
        assert_eq!(sr_error, SrError::InsufficientPrivileges);
    }

    #[test]
    fn test_from_serde_json_error() {
        let json_error = serde_json::from_str::<i32>("invalid json");
        assert!(json_error.is_err());

        let sr_error: SrError = json_error.unwrap_err().into();
        assert_eq!(sr_error, SrError::ConfigurationError);
    }

    #[test]
    fn test_error_propagation() {
        fn test_function() -> SrResult<()> {
            std::fs::File::open("/nonexistent/path")?;
            Ok(())
        }

        let result = test_function();
        assert!(result.is_err());
        // The exact error type depends on the IO error, but it should convert properly
        match result.unwrap_err() {
            SrError::ExecutionFailed | SrError::SystemError | SrError::PermissionDenied => {}
            other => panic!("Unexpected error type: {:?}", other),
        }
    }

    #[test]
    fn test_json_serialization_error_conversion() {
        use serde_json::Value;

        // Create a malformed JSON string
        let malformed_json = r#"{"incomplete": true"#;
        let result: Result<Value, serde_json::Error> = serde_json::from_str(malformed_json);

        let sr_error: SrError = result.unwrap_err().into();
        assert_eq!(sr_error, SrError::ConfigurationError);
    }

    #[test]
    fn test_error_chain() {
        // Test that errors can be chained and converted properly
        fn inner_function() -> Result<(), std::io::Error> {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Access denied",
            ))
        }

        fn outer_function() -> SrResult<()> {
            inner_function()?;
            Ok(())
        }

        let result = outer_function();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), SrError::PermissionDenied);
    }
}
