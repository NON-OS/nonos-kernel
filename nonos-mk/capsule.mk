# NØNOS shared capsule build/sign/verify macro.
#
# A `userland/<capsule>/Capsule.mk` declares the capsule's identity
# in CAPSULE_* variables and then `include nonos-mk/capsule.mk` to
# materialise the standard target set:
#
#   nonos-mk-<slug>            build the userland ELF
#   nonos-mk-<slug>-sign       sign cert + manifest under the baked
#                              trust-anchor policy
#   nonos-mk-check-<slug>-keys assert the publisher seeds + pubs are
#                              present
#   $(<slug>_BIN)              path to the userland ELF
#   $(<slug>_CERT)             path to the NØNOS-ID cert blob
#   $(<slug>_MANIFEST)         path to the CapsuleManifest v3 blob
#   $(<slug>_ARTIFACTS)        union of the three above
#
# All capsule-specific cert/manifest/key/endpoint/caps values live
# in the per-capsule Capsule.mk; the root Makefile is forbidden by
# the static gate from defining any of those.
#
# Implementation note: the per-capsule rules are wrapped in a
# `define ... endef` block and instantiated through `$(call ...)`
# so the slug is interpolated into the rule text at parse time.
# Without that, recipe text like `$(CAPSULE_SLUG)_HANDLE` would
# resolve to the *last* value of `CAPSULE_SLUG` (clobbered by the
# next include), breaking every capsule but the most recent.

ifndef CAPSULE_SLUG
$(error CAPSULE_SLUG must be set before including nonos-mk/capsule.mk)
endif
ifndef CAPSULE_BIN_NAME
$(error CAPSULE_BIN_NAME must be set in $(CAPSULE_SLUG) Capsule.mk)
endif
ifndef CAPSULE_DIR
$(error CAPSULE_DIR must be set in $(CAPSULE_SLUG) Capsule.mk)
endif
ifndef CAPSULE_HANDLE
$(error CAPSULE_HANDLE must be set in $(CAPSULE_SLUG) Capsule.mk)
endif
ifndef CAPSULE_DOMAIN
$(error CAPSULE_DOMAIN must be set in $(CAPSULE_SLUG) Capsule.mk)
endif
ifndef CAPSULE_NAMESPACE
$(error CAPSULE_NAMESPACE must be set in $(CAPSULE_SLUG) Capsule.mk)
endif
ifndef CAPSULE_SERVICE_ENDPOINT
$(error CAPSULE_SERVICE_ENDPOINT must be set in $(CAPSULE_SLUG) Capsule.mk)
endif
ifndef CAPSULE_REPLY_ENDPOINT
$(error CAPSULE_REPLY_ENDPOINT must be set in $(CAPSULE_SLUG) Capsule.mk)
endif
ifndef CAPSULE_REQUIRED_CAPS
$(error CAPSULE_REQUIRED_CAPS must be set in $(CAPSULE_SLUG) Capsule.mk)
endif

# The committed trust-bundle lives at `nonos-data/trust/`:
#   keys/    publisher .pub files (committed)
#   capsules/  *.nonos_id_cert.bin and *.manifest.bin (committed)
#   policy/   nonos_trust_anchor.policy.bin (committed)
# Seeds stay in `.keys/` (gitignored). The macro reads pubs from
# the committed `keys/` directory and writes cert + manifest into
# the committed `capsules/` directory so a clean checkout has
# everything the kernel verifier needs.
NONOS_BAKED_TRUST_DIR ?= nonos-data/trust

# Effective values with `$(or)` fallbacks. The reset block at the
# bottom of this file leaves the input vars defined-but-empty for
# the next include, so plain `?=` would not re-fire defaults. The
# `$(or)` form fires whenever the input is empty.
_NONOS_CAPSULE_OPTIONAL_CAPS := $(or $(CAPSULE_OPTIONAL_CAPS),0x0)
_NONOS_CAPSULE_CAPS_CEILING  := $(or $(CAPSULE_CAPS_CEILING),$(CAPSULE_REQUIRED_CAPS))
_NONOS_CAPSULE_TARGET        := $(or $(CAPSULE_TARGET),x86_64-nonos-user)
_NONOS_CAPSULE_VERSION       := $(or $(CAPSULE_VERSION),0.1.0)
_NONOS_CAPSULE_SERIAL        := $(or $(CAPSULE_ID_CERT_SERIAL),1)
# `$(or X,core,alloc)` parses as three args (X / core / alloc),
# returning `core` instead of the literal `core,alloc`. Use a
# comma variable so the default reaches `-Zbuild-std=` as one
# scalar.
_NONOS_CAPSULE_COMMA         := ,
_NONOS_CAPSULE_BUILD_STD     := $(or $(CAPSULE_BUILD_STD),core$(_NONOS_CAPSULE_COMMA)alloc)
_NONOS_CAPSULE_BUILD_STD_FEAT := $(or $(CAPSULE_BUILD_STD_FEATURES),compiler-builtins-mem)
_NONOS_CAPSULE_KEY_PUB_PREFIX := $(or $(CAPSULE_KEY_PUB_PREFIX),$(NONOS_BAKED_TRUST_DIR)/keys/$(CAPSULE_BIN_NAME)_publisher)
_NONOS_CAPSULE_KEY_SEED_PREFIX := $(or $(CAPSULE_KEY_SEED_PREFIX),.keys/$(CAPSULE_BIN_NAME)_publisher)
_NONOS_CAPSULE_METADATA      := $(or $(CAPSULE_METADATA),NØNOS $(CAPSULE_HANDLE) publisher v1)
_NONOS_CAPSULE_FEATURE       := $(or $(CAPSULE_FEATURE),nonos-capsule-$(CAPSULE_SLUG))

# Slug-namespaced variable snapshot. These are evaluated at
# include time so subsequent Capsule.mk files (which reassign
# CAPSULE_*) cannot disturb a prior capsule's metadata.
$(CAPSULE_SLUG)_DIR              := $(CAPSULE_DIR)
$(CAPSULE_SLUG)_BIN_NAME         := $(CAPSULE_BIN_NAME)
$(CAPSULE_SLUG)_TARGET           := $(_NONOS_CAPSULE_TARGET)
$(CAPSULE_SLUG)_BIN              := $(CAPSULE_DIR)/target/$(_NONOS_CAPSULE_TARGET)/release/$(CAPSULE_BIN_NAME)
$(CAPSULE_SLUG)_CERT             := $(NONOS_BAKED_TRUST_DIR)/capsules/$(CAPSULE_BIN_NAME).nonos_id_cert.bin
$(CAPSULE_SLUG)_MANIFEST         := $(NONOS_BAKED_TRUST_DIR)/capsules/$(CAPSULE_BIN_NAME).manifest.bin
$(CAPSULE_SLUG)_STALE            := $(NONOS_BAKED_TRUST_DIR)/capsules/$(CAPSULE_BIN_NAME).STALE
$(CAPSULE_SLUG)_KEY_ED_SEED      := $(_NONOS_CAPSULE_KEY_SEED_PREFIX)_ed25519.seed
$(CAPSULE_SLUG)_KEY_ED_PUB       := $(_NONOS_CAPSULE_KEY_PUB_PREFIX)_ed25519.pub
$(CAPSULE_SLUG)_KEY_MLDSA_SEED   := $(_NONOS_CAPSULE_KEY_SEED_PREFIX)_mldsa65.seed
$(CAPSULE_SLUG)_KEY_MLDSA_PUB    := $(_NONOS_CAPSULE_KEY_PUB_PREFIX)_mldsa65.pub
$(CAPSULE_SLUG)_HANDLE           := $(CAPSULE_HANDLE)
$(CAPSULE_SLUG)_DOMAIN           := $(CAPSULE_DOMAIN)
$(CAPSULE_SLUG)_RECOVERY         := $(CAPSULE_RECOVERY)
$(CAPSULE_SLUG)_NAMESPACE        := $(CAPSULE_NAMESPACE)
$(CAPSULE_SLUG)_SERVICE_ENDPOINT := $(CAPSULE_SERVICE_ENDPOINT)
$(CAPSULE_SLUG)_REPLY_ENDPOINT   := $(CAPSULE_REPLY_ENDPOINT)
$(CAPSULE_SLUG)_REQUIRED_CAPS    := $(CAPSULE_REQUIRED_CAPS)
$(CAPSULE_SLUG)_OPTIONAL_CAPS    := $(_NONOS_CAPSULE_OPTIONAL_CAPS)
$(CAPSULE_SLUG)_CAPS_CEILING     := $(_NONOS_CAPSULE_CAPS_CEILING)
$(CAPSULE_SLUG)_VERSION          := $(_NONOS_CAPSULE_VERSION)
$(CAPSULE_SLUG)_SERIAL           := $(_NONOS_CAPSULE_SERIAL)
$(CAPSULE_SLUG)_BUILD_STD        := $(_NONOS_CAPSULE_BUILD_STD)
$(CAPSULE_SLUG)_BUILD_STD_FEAT   := $(_NONOS_CAPSULE_BUILD_STD_FEAT)
$(CAPSULE_SLUG)_METADATA         := $(_NONOS_CAPSULE_METADATA)
$(CAPSULE_SLUG)_FEATURE          := $(_NONOS_CAPSULE_FEATURE)
$(CAPSULE_SLUG)_KERNEL_MIRROR    := $(CAPSULE_KERNEL_MIRROR)
$(CAPSULE_SLUG)_ARTIFACTS        := $($(CAPSULE_SLUG)_BIN) $($(CAPSULE_SLUG)_CERT) $($(CAPSULE_SLUG)_MANIFEST)

# Track all capsules that have included this macro so the root
# Makefile can iterate them through `$(NONOS_VERIFIED_CAPSULES)`.
# `:=` plus explicit reuse forces eager append — `+=` against a
# recursive variable would expand `$(CAPSULE_SLUG)` after the reset
# block clears it, leaving the list empty.
NONOS_VERIFIED_CAPSULES := $(NONOS_VERIFIED_CAPSULES) $(CAPSULE_SLUG)

# Per-capsule rules. The slug ($1) is interpolated at parse time
# through `$(eval $(call ...))`; literal `$$` survives `eval` to
# become a runtime `$` in the recipe.
define NONOS_CAPSULE_RULES

.PHONY: nonos-mk-$(1) nonos-mk-$(1)-sign nonos-mk-check-$(1)-keys

$$($(1)_BIN): $$(USERLAND_LIBC)
	@echo "Building $$($(1)_BIN_NAME) capsule..."
	@cd $$($(1)_DIR) && \
		RUSTUP_TOOLCHAIN=$$(TOOLCHAIN) \
		$$(CARGO) build --release --target ../x86_64-nonos-user.json \
		-Zbuild-std=$$($(1)_BUILD_STD) \
		$$(if $$($(1)_BUILD_STD_FEAT),-Zbuild-std-features=$$($(1)_BUILD_STD_FEAT),)
	@touch $$@

nonos-mk-$(1): $$($(1)_BIN)

nonos-mk-check-$(1)-keys:
	@for f in $$($(1)_KEY_ED_SEED) $$($(1)_KEY_ED_PUB) \
	          $$($(1)_KEY_MLDSA_SEED) $$($(1)_KEY_MLDSA_PUB); do \
	    [ -f "$$$$f" ] || { \
	        echo "::error::missing $$$$f — generate via: $$(CAPSULE_SIGN_BIN) keygen --alg <ed25519|mldsa65> --out <prefix>"; \
	        exit 1; \
	    }; \
	done

# nonos_id is BLAKE3(handle/domain/recovery); recompute every sign
# so a rename of the cert file cannot silently change the identity.
$(1)_NONOS_ID_HEX = $$(shell $$(CAPSULE_SIGN_BIN) derive-id \
	--handle $$($(1)_HANDLE) \
	--domain $$($(1)_DOMAIN) \
	--recovery "$$($(1)_RECOVERY)")

$$($(1)_CERT): $$(NONOS_TRUST_ANCHOR_POLICY_BIN) \
               $$($(1)_KEY_ED_PUB) $$($(1)_KEY_MLDSA_PUB) \
               $$(CAPSULE_SIGN_BIN) | nonos-mk-check-trust-keys nonos-mk-check-$(1)-keys
	@echo "Signing $$($(1)_HANDLE) NØNOS-ID certificate (hybrid)..."
	@$$(CAPSULE_SIGN_BIN) sign-id-cert \
		--serial $$($(1)_SERIAL) \
		--nonos-id $$($(1)_NONOS_ID_HEX) \
		--ns-glob $$($(1)_NAMESPACE) \
		--caps-ceiling $$($(1)_CAPS_CEILING) \
		--epoch $$(NONOS_TRUST_ANCHOR_EPOCH) \
		--valid-from-ms  $$(NONOS_CERT_VALID_FROM_MS) \
		--valid-until-ms $$(NONOS_CERT_VALID_UNTIL_MS) \
		--pub-key ed25519=$$($(1)_KEY_ED_PUB) \
		--pub-key mldsa65=$$($(1)_KEY_MLDSA_PUB) \
		--ta-seed ed25519=$$(NONOS_TA_ED25519_SEED) \
		--ta-seed mldsa65=$$(NONOS_TA_MLDSA65_SEED) \
		--metadata "$$($(1)_METADATA)" \
		--out $$@

# Manifest depends on the capsule ELF — rebuilding the ELF forces
# a manifest re-sign so payload_hash stays in sync.
$$($(1)_MANIFEST): $$($(1)_BIN) $$($(1)_CERT) \
                   $$(CAPSULE_SIGN_BIN) | nonos-mk-check-$(1)-keys
	@echo "Signing $$($(1)_HANDLE) capsule manifest..."
	@$$(CAPSULE_SIGN_BIN) sign-manifest \
		--cert $$($(1)_CERT) \
		--namespace $$($(1)_NAMESPACE) \
		--version $$($(1)_VERSION) \
		--target $$($(1)_TARGET) \
		--elf $$($(1)_BIN) \
		--required-caps $$($(1)_REQUIRED_CAPS) \
		--optional-caps $$($(1)_OPTIONAL_CAPS) \
		--endpoint $$($(1)_SERVICE_ENDPOINT) \
		--endpoint $$($(1)_REPLY_ENDPOINT) \
		--pub-seed ed25519=$$($(1)_KEY_ED_SEED) \
		--pub-seed mldsa65=$$($(1)_KEY_MLDSA_SEED) \
		--out $$@

nonos-mk-$(1)-sign: $$($(1)_CERT) $$($(1)_MANIFEST)

endef

$(eval $(call NONOS_CAPSULE_RULES,$(CAPSULE_SLUG)))

# Reset per-capsule input variables. The slug-prefixed snapshot
# above is permanent; clearing the source vars to empty (combined
# with the `$(or)` defaults above) is enough on GNU Make 3.81
# (Apple bundled), which lacks `undefine`.
CAPSULE_SLUG :=
CAPSULE_BIN_NAME :=
CAPSULE_DIR :=
CAPSULE_HANDLE :=
CAPSULE_DOMAIN :=
CAPSULE_RECOVERY :=
CAPSULE_NAMESPACE :=
CAPSULE_SERVICE_ENDPOINT :=
CAPSULE_REPLY_ENDPOINT :=
CAPSULE_REQUIRED_CAPS :=
CAPSULE_OPTIONAL_CAPS :=
CAPSULE_CAPS_CEILING :=
CAPSULE_TARGET :=
CAPSULE_VERSION :=
CAPSULE_ID_CERT_SERIAL :=
CAPSULE_BUILD_STD :=
CAPSULE_BUILD_STD_FEATURES :=
CAPSULE_KEY_PUB_PREFIX :=
CAPSULE_KEY_SEED_PREFIX :=
CAPSULE_METADATA :=
CAPSULE_FEATURE :=
CAPSULE_KERNEL_MIRROR :=
_NONOS_CAPSULE_OPTIONAL_CAPS :=
_NONOS_CAPSULE_CAPS_CEILING :=
_NONOS_CAPSULE_TARGET :=
_NONOS_CAPSULE_VERSION :=
_NONOS_CAPSULE_SERIAL :=
_NONOS_CAPSULE_BUILD_STD :=
_NONOS_CAPSULE_BUILD_STD_FEAT :=
_NONOS_CAPSULE_KEY_PUB_PREFIX :=
_NONOS_CAPSULE_KEY_SEED_PREFIX :=
_NONOS_CAPSULE_METADATA :=
_NONOS_CAPSULE_FEATURE :=
