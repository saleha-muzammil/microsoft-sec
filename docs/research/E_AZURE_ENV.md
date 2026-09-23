# Azure environment — verified facts (2026-09-22)

Checked directly against the live subscription, not assumed.

## Subscription

| Property | Value |
|---|---|
| Subscription | `Azure subscription 1` |
| Subscription ID | `03ddc744-6eff-45bf-964b-d1f409736052` |
| Tenant ID | `f151f019-540c-4c2f-827e-d86c8fc44c9d` |
| Signed-in user | `rmughees1@gmail.com` |
| **Offer type** | `Sponsored_2016-01-01` → **Azure Sponsorship (credits)** |
| **Spending limit** | **Off** |
| State | Enabled |

**Why this matters:** a Sponsorship subscription with the spending limit *off* will not hard-stop resource
creation the way a Free Trial does. We can deploy Foundry, Azure AI Search, and Container Apps without
hitting the classic "spending limit reached, subscription disabled" wall that kills hackathon demos.
Credits are still finite — see cost discipline below.

## Existing resources

- **No Cognitive Services / AI Foundry accounts exist yet.** Clean slate; we create ours.
- Existing resource groups are unrelated to this project (`cloud-shell-storage-eastus`, `blacksea-lab`,
  `pentest-research-rg`, `NetworkWatcherRG`). **We will create a dedicated resource group** so everything
  we build is isolated and can be torn down in one command.

## Resource providers — was a blocker, now fixed

All of these were `NotRegistered` and have been registered (registration is free and non-destructive,
but it must propagate before resource creation, which is why it was done early):

| Provider | State |
|---|---|
| `Microsoft.CognitiveServices` | ✅ Registered |
| `Microsoft.Search` | ✅ Registered |
| `Microsoft.App` | ✅ Registered |
| `Microsoft.ContainerRegistry` | ✅ Registered |
| `Microsoft.MachineLearningServices` | ✅ Registered |
| `Microsoft.OperationalInsights` | ✅ Was already registered |

> Had we not caught this, the first `az cognitiveservices account create` would have failed with a
> `MissingSubscriptionRegistration` error at the worst possible moment.

## Model quota — confirmed available (TPM, thousands)

Queried after provider registration. `0 / N` means **nothing consumed, N available**.

| Model | SKU | eastus | eastus2 | swedencentral |
|---|---|---|---|---|
| **gpt-5-mini** | GlobalStandard | **500** | **500** | **500** |
| **gpt-5.4-mini** | DataZoneStandard | **1000** | **1000** | **1000** |
| **o4-mini** | Standard | 1000 | 1000 | 1000 |
| gpt-4o | Standard | 150 | 150 | 150 |
| gpt-4o | GlobalStandard | 0 ⚠️ | — | — |
| gpt-4o-mini | Standard | 450 | 450 | 450 |
| **text-embedding-3-large** | Standard | 350 | 350 | 350 |
| text-embedding-3-small | GlobalStandard | 1000 | 1000 | 1000 |

⚠️ **Gotcha found:** `GlobalStandard.gpt-4o` is **0** in eastus while `Standard.gpt-4o` is 150. If a
deployment is attempted with the wrong SKU it fails on quota even though "gpt-4o quota" appears to exist.
The SKU matters as much as the model name.

### Recommended deployments

1. **`gpt-5-mini` (GlobalStandard)** — primary reasoning/agent model. 500K TPM is far more than a demo
   needs, it is inexpensive, and it is current-generation, which reads better to judges than gpt-4o.
2. **`text-embedding-3-large` (Standard)** — embeddings for the Azure AI Search index over baseline text.
3. Optionally **`o4-mini`** for the control-mapping agent, where slower, more careful reasoning is
   worth it and volume is low.

**Region: `eastus2`.** It carries the full quota set we need and has the broadest Foundry Agent Service
availability. (`eastus` is equally good on quota; `eastus2` is the safer default for agent features.)

## Local toolchain — verified present

| Tool | Version | Why it matters |
|---|---|---|
| Azure CLI | 2.88.0 | logged in, sponsorship sub active |
| Python | 3.11 / 3.12 / 3.13 / 3.14 | **use 3.12** — Azure SDK wheels lag on 3.14 |
| `uv` | installed | fast dependency installs under time pressure |
| **Java** | **OpenJDK 21.0.6 (Temurin)** | ⭐ **NIST `oscal-cli` is a Java tool — it will run natively here and in CI.** This makes "our OSCAL validates against the official NIST validator" a claim we can actually demo. |
| `gh` | authed as `mughees-urrehman` | repo publishing |
| `pdftotext` | present | used to extract the rules PDF |

## Cost discipline

- Sponsorship credits are finite; the spending limit being off means overspend is *possible*.
- Use `gpt-5-mini` as the default model, not a frontier model.
- Azure AI Search: use the **Free** or **Basic** tier. Free tier (50 MB, 3 indexes) is sufficient for
  baseline documents and costs nothing.
- Put everything in **one resource group** so teardown is `az group delete` — one command, no orphans.
- Deployment to Container Apps is a *nice-to-have*; a local demo satisfies the rules. Do not burn
  credits on it until the core works.
