package relay

// An all-zero quota means shared physical capacity, not a zero-byte allocation.
// Partially specified quotas remain invalid. Only operator-issued self-hosted
// entitlements select this policy; hosted tenants retain positive ceilings.
func (q TenantQuota) UsesSharedCapacity() bool { return q == (TenantQuota{}) }
func (q TenantQuota) Valid() bool {
	return q.UsesSharedCapacity() || (q.MaximumDomainCount > 0 && q.MaximumAggregateMessageCount > 0 &&
		q.MaximumAggregateMessageByteCount > 0 && q.MaximumAggregateBlobCount > 0 && q.MaximumAggregateBlobByteCount > 0)
}
func (r TenantRegistration) Quota() TenantQuota {
	return TenantQuota{r.MaximumDomainCount, r.MaximumAggregateMessageCount,
		r.MaximumAggregateMessageByteCount, r.MaximumAggregateBlobCount, r.MaximumAggregateBlobByteCount}
}
func (r TenantRegistration) UsesSharedCapacity() bool { return r.Quota().UsesSharedCapacity() }
func (r DomainRegistration) UsesSharedCapacity() bool {
	return r.MaximumMessageCount == 0 && r.MaximumMessageByteCount == 0 && r.MaximumBlobCount == 0 && r.MaximumBlobByteCount == 0
}
func (r DomainRegistration) WithSharedCapacity() DomainRegistration {
	r.MaximumMessageCount, r.MaximumMessageByteCount, r.MaximumBlobCount, r.MaximumBlobByteCount = 0, 0, 0, 0
	return r
}

// ApplyCapacityPolicy is server-side normalization after tenant authorization.
// A client-supplied per-Space default never allocates storage for a self-hosted
// account. Conversely a client cannot remove a hosted domain's issued limits.
func (r TenantRegistration) ApplyCapacityPolicy(domain DomainProvisioning) (DomainProvisioning, error) {
	if r.UsesSharedCapacity() {
		domain.Registration = domain.Registration.WithSharedCapacity()
	} else if domain.Registration.UsesSharedCapacity() {
		return DomainProvisioning{}, protocolError(CodeInvalidDomain, "bounded tenant requires explicit domain limits")
	}
	return domain, nil
}
