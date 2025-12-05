void
grub_disk_close (grub_disk_t disk)
{
  /* ... existing code ... */
  /* Free hardware name if allocated */
  if (disk->hw_name)
    grub_free (disk->hw_name);
}