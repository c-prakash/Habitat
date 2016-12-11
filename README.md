#Sitecore Habitat

Habitat is a Sitecore solution example built on a modular architecture.
The architecture and methodology focuses on:

* Simplicity - *A consistent and discoverable architecture*
* Flexibility - *Change and add quickly and without worry*
* Extensibility - *Simply add new features without steep learning curve*

For more information, please check out the [Habitat Wiki](../../wiki)

Extending Habitat to support Claims Identity, implementation from - https://cprakash.com/2015/02/02/sitecore-with-claimsidentity/

What is needed to make it work.
1) Copy the output DLLs from bin folder to destination bin folder
2) Place the Foundation.ClaimsSecurity.config under App_config/Include folder

If you are following the Habitat script, it will automatically take care both steps for you.

Caveat - Solution run into issues in preview mode. A workaround would be to not deploy the Foundation.ClaimsSecurity.config file in CMS environment.
