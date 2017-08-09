# Lagopus2 Module Design

## Definitions

- Module class

  A template for the module.

- Module instance

  An instance created from the Module Class.

## Current Module Class Definition
- name (property)

  A name of the module.

- context_size (property)

  A size of context for this class.

- ctrlconf (method)

  An array of control APIs. This set of APIs may be called for the module class as well as the individual module instance.

- class_init (method)

  Called when the class is loaded to Lagopus.
  E.g. initialize DPDK core.

- class_fini (method)

  Called when the class is unloaded from Lagopus.
  Not used at the moment.

- create_hook (method)

  Called when the module is instantiated.
  Not used at the moment.

- destory_hook  (method)

  Not used. Supposed to be called when the module is destoryed?

- configure (method)

  Called via 'vsw_module_configure()'

- unconfigure (method)

  Not used.

- main (method)

  Continuously called from a thread. Supposed to dequeue input, process and forward 'mbuf' to the next hop by calling the input method of the next module set in the module's output.

  This method is called frequently from the thread. However, there's no rule on how this main method should return to the caller when its done.

- stats (method)

  Not used. Supposed to provide module status?

- input (method)

  Takes mbuf input. Currently, depending on the module, it processes the packet immediately, or enqueue the mbuf to its queue.

## Design Proposal

- No input method. Use userspace RCU lock-free queue to pass mbuf to the next module.
- Main routine should be called only when mbuf arrives to the queue. We need to check how we can gracefully wait. We don't want to poll here.
- Wraps C module library, with Go. Basically, the module is wrapped with Go, and may be written entirely with Go.
