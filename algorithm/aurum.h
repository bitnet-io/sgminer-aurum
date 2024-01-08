int aurum_test(unsigned char *pdata, const unsigned char *ptarget, uint32_t nonce);
void aurum_regenhash(struct work *work);
bool scanhash_aurum(struct thr_info *thr, const unsigned char __maybe_unused *pmidstate,
                     unsigned char *pdata, unsigned char __maybe_unused *phash1,
                     unsigned char __maybe_unused *phash, const unsigned char *ptarget,
                     uint32_t max_nonce, uint32_t *last_nonce, uint32_t n);


