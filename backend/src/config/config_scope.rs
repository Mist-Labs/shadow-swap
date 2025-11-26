use actix_web::web;

use crate::api::routes::{
    get_metrics, get_stats, get_swap_status, health_check, indexer_event, initiate_swap, root,
};

pub fn configure(conf: &mut web::ServiceConfig) {
    let scope = web::scope("/api/v1")
        .service(initiate_swap)
        .service(indexer_event)
        .service(root)
        .service(health_check)
        .service(get_metrics)
        .service(get_stats)
        .service(get_swap_status);

    conf.service(scope);
}
