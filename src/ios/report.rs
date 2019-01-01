use crate::ios::aasa;
use crate::ios::entitlements::{self, Entitlements};

pub fn report_problems_human(
    aasa_problems: Option<Vec<aasa::Problem>>,
    aasa: Option<aasa::CheckResult>,
    entitlement_problems: Option<Vec<entitlements::Problem>>,
    entitlements: Option<Entitlements>,
) {
    // TODO: report positive results as well?
    if let Some(aasa_problems) = aasa_problems {
        for problem in aasa_problems {
            println!("{}", problem.to_string_human());
        }
    }
    if let Some(entitlement_problems) = entitlement_problems {
        for problem in entitlement_problems {
            println!("{}", problem.to_string_human());
        }
    }
}
