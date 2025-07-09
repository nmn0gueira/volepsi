import csv, random, string, os, argparse

def generate_random_id(length=8):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def generate_csv_files(sender_count, receiver_count, intersection_count, associated_columns, sender_file='sender.csv', receiver_file='receiver.csv'):
    assert intersection_count <= min(sender_count, receiver_count), "Intersection cannot exceed total counts"

    intersection_ids = {generate_random_id() for _ in range(intersection_count)}
    
    while len(intersection_ids) < intersection_count:
        intersection_ids.add(generate_random_id())

    remaining_sender_ids = {generate_random_id() for _ in range(sender_count - intersection_count)}
    while len(remaining_sender_ids) < (sender_count - intersection_count):
        remaining_sender_ids.add(generate_random_id())

    remaining_receiver_ids = {generate_random_id() for _ in range(receiver_count - intersection_count)}
    while len(remaining_receiver_ids) < (receiver_count - intersection_count):
        remaining_receiver_ids.add(generate_random_id())

    sender_ids = list(intersection_ids.union(remaining_sender_ids))
    receiver_ids = list(intersection_ids.union(remaining_receiver_ids))

    with open(sender_file, 'w', newline='') as f:
        writer = csv.writer(f)
        for id_ in sender_ids:
            row = [id_] + [random.randrange(0, 1000) for _ in range(associated_columns)]
            writer.writerow(row)

    with open(receiver_file, 'w', newline='') as f:
        writer = csv.writer(f)
        for id_ in receiver_ids:
            writer.writerow([id_])

    print(f"Generated {sender_file} and {receiver_file}.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='generates input for mp-spdz sample programs')
    
    parser.add_argument('-s', default=10, type=int, 
        help="sender length")
    parser.add_argument('-r', default=10, type=int, 
        help="receiver length")
    parser.add_argument('-i', default=0, type=int,
        help="intersection count")
    parser.add_argument('-a', default=0, type=int,
        help="number of associated columns (only relevant for cpsi)")
    parser.add_argument('-o', default="data", type=str,
        help="output directory")
    parser.add_argument('--sender_file', default='sender.csv', type=str,
        help="output file for sender data")
    parser.add_argument('--receiver_file', default='receiver.csv', type=str,
        help="output file for receiver data")
    
    args = parser.parse_args()

    generate_csv_files(
            sender_count=args.s,
            receiver_count=args.r,
            intersection_count=args.i,
            associated_columns=args.a,
            sender_file=args.o + '/' + args.sender_file,
            receiver_file=args.o + '/' + args.receiver_file
    )
