# Documentation layout

## Structure

- `docs/Agents/`: native SSHD/Fail2Ban guides and option catalogues for implementation and operation.
- `docs/Agents/Spec/`: implementation and migration plans.
- `docs/Tech/features/`: operator-authored feature notes.
- `docs/Tech/*.canvas`: Obsidian feature maps; file nodes are relative to the `docs` vault root.
- `docs/.obsidian/`: shared vault settings. Editor workspace/session files are not versioned.

## Migration

1. Move the three SSHD/Fail2Ban documents into `Agents` without regressing their current contents. The operator's moved `sshd.md` copy matched the earlier limited-API version; retain the complete guide from `master` instead.
2. Add the existing APT/swapfile feature notes, feature-map canvas and shared Obsidian settings unchanged.
3. Preserve document-relative links between the three guides and verify canvas file targets from the vault root.
4. Publish documentation separately from code formatting and infrastructure state; update the consuming MyIaC submodule pin in a documentation-only change.

The feature notes retain their operator-authored draft status. This migration changes documentation organization, not provider behavior or deployment state.
