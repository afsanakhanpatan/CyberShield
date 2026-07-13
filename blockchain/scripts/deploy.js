const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
  console.log("Starting deployment of CyberShield Registry & Token contracts...");

  // Compile contracts if needed
  await hre.run("compile");

  // Deploy Registry
  const CyberShieldRegistry = await hre.ethers.getContractFactory("CyberShieldRegistry");
  const registry = await CyberShieldRegistry.deploy();
  await registry.waitForDeployment();
  const registryAddress = await registry.getAddress();
  console.log(`CyberShieldRegistry deployed successfully to: ${registryAddress}`);

  // Deploy ShieldToken
  const ShieldToken = await hre.ethers.getContractFactory("ShieldToken");
  const token = await ShieldToken.deploy();
  await token.waitForDeployment();
  const tokenAddress = await token.getAddress();
  console.log(`ShieldToken deployed successfully to: ${tokenAddress}`);

  // Write registry address to blockchain directory for backend usage
  fs.writeFileSync(
    path.join(__dirname, "../deployed_address.txt"),
    registryAddress
  );
  console.log("Wrote registry address to backend config.");

  // Create dashboard source directory if it doesn't exist, and write address there
  const dashboardDir = path.join(__dirname, "../../dashboard/src");
  if (!fs.existsSync(dashboardDir)) {
    fs.mkdirSync(dashboardDir, { recursive: true });
  }
  
  fs.writeFileSync(
    path.join(dashboardDir, "contract_address.json"),
    JSON.stringify({ 
      registry: registryAddress,
      token: tokenAddress,
      address: registryAddress // backward compatibility
    }, null, 2)
  );
  console.log("Wrote deployed addresses to React dashboard config.");
  
  // Save the contract ABI to React dashboard for Ethers integration
  const registryArtifact = path.join(__dirname, "../artifacts/contracts/CyberShieldRegistry.sol/CyberShieldRegistry.json");
  if (fs.existsSync(registryArtifact)) {
    const artifact = JSON.parse(fs.readFileSync(registryArtifact, "utf8"));
    fs.writeFileSync(
      path.join(dashboardDir, "CyberShieldRegistryABI.json"),
      JSON.stringify(artifact.abi, null, 2)
    );
    console.log("Wrote registry ABI to React dashboard config.");
  }

  // Save Token ABI to React dashboard
  const tokenArtifact = path.join(__dirname, "../artifacts/contracts/ShieldToken.sol/ShieldToken.json");
  if (fs.existsSync(tokenArtifact)) {
    const artifact = JSON.parse(fs.readFileSync(tokenArtifact, "utf8"));
    fs.writeFileSync(
      path.join(dashboardDir, "ShieldTokenABI.json"),
      JSON.stringify(artifact.abi, null, 2)
    );
    console.log("Wrote token ABI to React dashboard config.");
  }
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
