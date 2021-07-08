use crate::report::Host;
use std::{sync::Arc, time::Duration};
use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    name_server::{GenericConnection, GenericConnectionProvider, TokioRuntime},
    AsyncResolver,
};

pub type Resolver = Arc<AsyncResolver<GenericConnection, GenericConnectionProvider<TokioRuntime>>>;

pub async fn resolves(dns_resolver: &Resolver, host: &Host) -> bool {
    if dns_resolver.lookup_ip(host.domain.as_str()).await.is_ok() {
        return true;
    }

    false
}

pub fn new_resolver() -> Resolver {
    let resolver = AsyncResolver::tokio(
        ResolverConfig::default(),
        ResolverOpts {
            timeout: Duration::from_secs(4),
            ..Default::default()
        },
    )
    .expect("dns/new_resolver: building DNS client");

    return Arc::new(resolver);
}
