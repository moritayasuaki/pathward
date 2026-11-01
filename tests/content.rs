use pathward::content::*;
#[test]
fn ranges_and_shared_freshness_fail_closed_at_all_boundaries() {
    let max = pathward::serving::MAX_FILE_BYTES;
    assert!(span_allowed(max, max, 0));
    assert!(span_allowed(max, 0, max));
    for args in [
        (max + 1, 0, 0),
        (max, max, 1),
        (max, max + 1, 0),
        (max, 1, u64::MAX),
        (0, u64::MAX, 2),
    ] {
        assert!(!span_allowed(args.0, args.1, args.2));
    }
    for status in [200, 206, 304] {
        assert!(shared_cache_allowed(status, true, false, 31536000));
        assert!(!shared_cache_allowed(status, false, false, 60));
        assert!(!shared_cache_allowed(status, true, true, 60));
        assert!(!shared_cache_allowed(status, true, false, 31536001));
    }
    for status in [101, 301, 308, 400, 401, 403, 404, 412, 416, 500] {
        assert!(!shared_cache_allowed(status, true, false, 60));
    }
}
#[test]
fn entity_tag_conditions_dominate_dates_and_failures_dominate_revalidation() {
    assert_eq!(
        precondition_status(Some(false), Some(true), Some(true), Some(true)),
        412
    );
    assert_eq!(
        precondition_status(Some(true), Some(false), Some(false), Some(true)),
        200
    );
    assert_eq!(
        precondition_status(None, Some(false), Some(true), None),
        412
    );
    assert_eq!(
        precondition_status(None, None, Some(false), Some(true)),
        200
    );
    assert_eq!(
        precondition_status(None, None, Some(true), Some(false)),
        304
    );
    assert_eq!(precondition_status(None, None, None, Some(true)), 304);
    assert_eq!(precondition_status(None, None, None, None), 200);
}
