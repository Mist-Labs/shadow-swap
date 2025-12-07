use actix_web::web;

use crate::api::routes::{
    convert_amount, get_all_prices, get_metrics, get_price, get_stats, get_swap_status, health_check, indexer_event, initiate_swap, root
};

pub fn configure(conf: &mut web::ServiceConfig) {
    let scope = web::scope("/api/v1")
        .service(initiate_swap)
        .service(indexer_event)
        .service(root)
        .service(health_check)
        .service(get_metrics)
        .service(get_stats)
        .service(convert_amount)
        .service(get_price)
        .service(get_all_prices)
        .service(get_swap_status);

    conf.service(scope);
}
